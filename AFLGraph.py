"""
    This file is part of AFL-Cast.

    AFL-Cast is free software: you can redistribute it and/or modify it under the terms of the 
    GNU General Public License as published by the Free Software Foundation, either version 3 
    of the License, or (at your option) any later version.

    AFL-Cast is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with AFL-Cast. 
    If not, see <https://www.gnu.org/licenses/>. 

"""

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmConstraint
from miasm.expression.expression import ExprId
import miasm
import lief


def attr2str(default_attr, attr):
    return " ".join(
        '%s="%s"' % (name, value)
        for name, value in dict(default_attr, **attr).viewkeys()
    )


def get_afl_maybe_log(binary):
    # get all afl_maybe_log functions
    elf = lief.parse(binary)
    symbols = elf.symbols
    afl_maybe_logs = []
    for sym in symbols:
        if sym.name == "__afl_maybe_log":
            afl_maybe_logs.append(sym.value)
    return afl_maybe_logs


class AFLBlock:
    def __init__(self, address):
        self.address = address
        self.block_id = 0
        self.successors = []
        self.hit = False
        self.visited = False

    def __str__(self):
        return "AFLBlock(0x%.8x, 0x%.4x, [%.4d], %s)" % (
            self.address,
            self.block_id,
            len(self.successors),
            ["False", "True"][int(self.hit)],
        )


class AFL:
    def __init__(self, binary, bitmap, function, follow_call=True, dont_dis=[]):
        self.binary = binary
        self.bitmap = bitmap
        self.function = function
        self.loc_db = LocationDB()

        self.cont = Container.from_stream(open(self.binary, "rb"), self.loc_db)
        self.afl_maybe_logs = get_afl_maybe_log(self.binary)
        if len(self.afl_maybe_logs) == 0:
            print("[-] The Input binary does not have AFL Instrumentation. Exiting.")
            exit(-1)
        # add __afl_maybe_log name to location
        temp = 0
        for addr in self.afl_maybe_logs:
            loc_key = self.loc_db.get_or_create_offset_location(addr)
            self.loc_db.add_location_name(loc_key, "__afl_maybe_log_%d" % temp)
            dont_dis.append("__afl_maybe_log_%d" % temp)
            temp += 1

        self.machine = Machine(self.cont.arch)
        self.aflgraph = None

        # try to see if function exists in binary
        self.function_offset = self.cont.loc_db.get_name_offset(self.function)
        if self.function_offset is None:
            print('[-] No "%s" function found in the provided binary' % self.function)
            exit(-1)

        self.mdis = self.machine.dis_engine(
            self.cont.bin_stream, loc_db=self.cont.loc_db
        )

        self.mdis.follow_call = follow_call
        for i in range(len(dont_dis)):
            if type(dont_dis[i]) == str:
                dont_dis[i] = self.cont.loc_db.get_name_offset(dont_dis[i])
            if type(dont_dis[i]) == miasm.expression.expression.LocKey:
                dont_dis[i] = self.cont.loc_db.get_location_offset(dont_dis[i])

        self.mdis.dont_dis = dont_dis
        self.asmcfg = self.mdis.dis_multiblock(self.function_offset)

    def get_dot(self, filename):
        with open(filename, "w") as file:
            file.write(self.asmcfg.dot())
            file.close()

    def get_block(self, offset):
        loc_key = self.cont.loc_db.get_offset_location(offset)
        block = self.asmcfg.loc_key_to_block(loc_key)
        if block is None:
            block = list(self.get_dis_cfg(offset).blocks)[0]
            self.asmcfg.add_block(block)
            self.asmcfg.rebuild_edges()
        return block

    def get_dis_cfg(self, offset):
        follow_call = self.mdis.follow_call
        self.mdis.follow_call = False
        asmcfg = self.mdis.dis_multiblock(offset)
        return asmcfg

    def get_location_offset(self, loc):
        return self.cont.loc_db.get_location_offset(loc)

    def get_leaf_nodes(self, loc_key):
        offset = self.cont.loc_db.get_location_offset(loc_key)
        mdis_option = self.mdis.follow_call
        self.mdis.follow_call = False
        asmcfg = self.mdis.dis_multiblock(offset)
        leafs = []
        for block in asmcfg.blocks:
            if len(asmcfg.successors(block.loc_key)) < 1:
                leafs.append(block.loc_key)
        self.mdis.follow_call = mdis_option
        return leafs

    def get_afl_graph(self):

        if self.aflgraph is None:
            head = self.get_block(
                self.cont.loc_db.get_location_offset(self.asmcfg.heads()[0])
            )
            self.aflgraph = AFLGraph(self, head)
            self.aflgraph.process_pending_edges()
        return self.aflgraph

    def get_afl_blockid(self, block):
        offset = self.cont.loc_db.get_location_offset(block)
        lines = self.get_block(offset).lines
        for i in range(len(lines)):
            if lines[i].name == "PUSH" and lines[i].args[0].is_loc():
                offset = self.loc_db.get_location_offset(lines[i].args[0].loc_key)
                if offset in self.afl_maybe_logs:
                    if isinstance(lines[i - 1].args[1], ExprId):
                        __import__("pdb").set_trace()
                    return int(lines[i - 1].args[1])
        return False


class AFLGraph:
    def __init__(self, context, head):
        self.context = context
        self.cache = {}
        self.asmcfg = context.asmcfg
        self.head = head
        self.root = self.get_block_by_addr(self.head.get_offsets()[0])
        self.edges = []
        self.pending_edges = []
        return self.build_graph(head, self.root, self.root)

    def is_switch(self, loc_key):
        curr_block = self.asmcfg.loc_key_to_block(loc_key)
        if curr_block.lines[-1].name == "JMP":
            dst = curr_block.lines[-1].getdstflow(self.context.loc_db)[0]
            if dst.is_loc() is False:
                return True
        return False

    def is_valid_destination(self, loc_key):
        curr_block = self.asmcfg.loc_key_to_block(loc_key)
        if curr_block is None:
            curr_block = list(
                self.context.get_dis_cfg(
                    self.context.loc_db.get_location_offset(loc_key)
                ).blocks
            )[0]
            self.asmcfg.add_block(curr_block)
            self.asmcfg.rebuild_edges()
        if (
            len(curr_block.lines) < 3
            and curr_block.lines[-1].name == "JMP"
            and curr_block.lines[-1].getdstflow(self.context.loc_db)[0].is_loc()
            is False
        ):
            return False
        return True

    def get_next_afl_blocks(self, curr_block):
        curr_block_id = self.context.get_afl_blockid(curr_block.loc_key)
        if curr_block_id is not False:
            return [curr_block.loc_key]

        if len(self.asmcfg.successors(curr_block.loc_key)) < 1:
            return None

        afl_blocks = []
        successors = self.asmcfg.successors(curr_block.loc_key)

        # special case: where we will only have 1 call to __afl_maybe_log
        # and that too inside the function which is being called. We detect this case
        # by checking if the number of successors of curr_block is 2. If it is 2, then
        # we check the next block after curr_block as afl_id or not. If it does not have
        # afl_id then we return only the afl_id in the call destination.
        # example:
        # curr_block:
        #     mov     r12, rax
        #     xor     eax, eax
        #     call    init          # we will have one afl_maybe_log inside this function)
        # next_block:
        #     mov     rsi, [argv+8] # since, we do not have afl id in the next block
        #     mov     rbp, rax      # we only return the afl id from above function ("init")
        #     mov     rdi, bin
        #     call    load_file

        if len(successors) == 2:
            next_block = curr_block.get_next()
            next_block_aflid = self.context.get_afl_blockid(next_block)
            if next_block_aflid is False:
                successors.remove(next_block)
                successor_aflid = self.context.get_afl_blockid(successors[0])
                if successor_aflid is not False:
                    return [successors[0]]
                else:
                    return None

        for succ in successors:
            succ_block = self.asmcfg.loc_key_to_block(succ)
            res = self.get_next_afl_blocks(succ_block)
            if res is not None:
                afl_blocks += res

        return afl_blocks

    def handle_calls(self, curr_block):
        instr = curr_block.lines[-1]
        dst = instr.getdstflow(self.context.cont.loc_db)[0]
        if dst.is_loc():  # must make sure call destination is valid location
            if self.is_valid_destination(dst.loc_key):
                # get all leaf nodes from destination
                leaves = self.context.get_leaf_nodes(dst.loc_key)

                # get return address location key
                return_block_loc = curr_block.get_next()

                # get return address block
                return_block = self.asmcfg.loc_key_to_block(return_block_loc)
                if return_block is None:
                    return_block = list(
                        self.context.get_dis_cfg(
                            self.context.loc_db.get_location_offset(return_block_loc)
                        ).blocks
                    )[0]
                    self.asmcfg.add_block(return_block)
                    self.asmcfg.rebuild_edges()
                # get the blocks which has afl id and occur
                # right after the return block
                afl_blocks_after_return_block = self.get_next_afl_blocks(return_block)

                if afl_blocks_after_return_block is None:
                    return None

                for leaf in leaves:

                    # for each leaf that has afl id
                    # and for each return afl block
                    # get the edges and see if they were hit
                    leaf_afl_id = self.context.get_afl_blockid(leaf)
                    if leaf_afl_id is False:
                        continue
                    for retblock in afl_blocks_after_return_block:
                        self.pending_edges.append([leaf, retblock])

    def handle_switch_cases(self, curr_block):
        # try to find the jmp table
        instr = curr_block.lines[-1]
        for i in range(len(curr_block.lines)):
            if curr_block.lines[::-1][i].name == "LEA":
                instr = curr_block.lines[::-1][i]
                nextr = curr_block.lines[::-1][i - 1]
                break
        if instr.name == "LEA":
            jmptbl = instr.args[1]
            rel_off = jmptbl.ptr.args[1].arg
            base = nextr.offset
            jmptbl = base + rel_off
        else:
            return

        # read jump table
        with open(self.context.binary, "rb") as file:
            data = file.read()
            file.close()

        jmptbl_l = []
        temp = 0xFFFFFFFF

        import struct

        i = 0
        while (temp & 0xFF000000) == (0xFF << 24):
            temp = struct.unpack("<I", data[jmptbl + i * 4 : jmptbl + (i + 1) * 4])[0]
            jmptbl_l.append(temp)
            i += 1

        jmptbl_l.pop()
        jmptbl_l = list(set(jmptbl_l))
        del struct

        for target in jmptbl_l:
            address = jmptbl + (target - 2 ** 32)
            target_asmcfg = self.context.get_dis_cfg(address)
            target_block = list(target_asmcfg.blocks)[0]
            switch_candidate = target_block
            self.asmcfg.merge(target_asmcfg)
            # self.asmcfg.add_block(target_block)
            self.asmcfg.add_edge(
                curr_block.loc_key, target_block.loc_key, AsmConstraint.c_to
            )

            # not all switch blocks end with "JMP" (0x166a)
        #             while target_block.lines[-1].name != "JMP":
        #                 if target_block.lines[-1].name in ["CALL"]:
        #                     self.handle_calls(target_block)
        #
        #                 next_block_loc_key = target_block.get_next()
        #                 next_block = target_asmcfg.loc_key_to_block(next_block_loc_key)
        #                 self.asmcfg.add_block(next_block)
        #                 self.asmcfg.add_edge(target_block.loc_key, next_block_loc_key, AsmConstraint.c_next)
        #                 target_block = next_block
        #
        #             curr_block = target_block
        #             parent = self.get_block_by_addr(switch_candidate.get_offsets()[0])
        #             curr = self.get_block_by_addr(curr_block.get_offsets()[0])
        #             self.build_graph(curr_block, parent, curr)

        self.asmcfg.rebuild_edges()
        switch_dispatch_block = curr_block
        switch_dispatch_block_offset = switch_dispatch_block.get_offsets()[0]
        parent = self.get_block_by_addr(switch_dispatch_block_offset)
        for successor in self.asmcfg.successors(switch_dispatch_block.loc_key):
            curr_block = self.asmcfg.loc_key_to_block(successor)
            curr = self.get_block_by_addr(curr_block.get_offsets()[0])
            self.build_graph(curr_block, parent, curr)

    def build_graph(self, curr_block, parent, curr):
        """Builds the graph of all AFL instrumented Basic Blocks"""
        # curr_block is now visited
        curr.visited = True

        # if it has successors but it does not have afl id
        afl_blockid = self.context.get_afl_blockid(curr_block.loc_key)

        # if its a leaf node
        if len(self.asmcfg.successors(curr_block.loc_key)) < 1:
            # if its a call to plt or indirect call then return

            if not self.is_valid_destination(curr_block.loc_key):
                return

            # if the leaf node does have aflid
            if afl_blockid is not False:
                curr.block_id = afl_blockid
                parent.successors.append(curr)
                self.edges.append([parent, curr])
                if self.is_switch(curr_block.loc_key):
                    self.handle_switch_cases(curr_block)
                return
            return

        # if the node has successors and does not have afl id
        if afl_blockid is False:

            # traverse through its successors
            for successor in self.asmcfg.successors_iter(curr_block.loc_key):

                # detect loops
                succ_offset = self.context.get_location_offset(successor)
                succ_block = self.asmcfg.loc_key_to_block(successor)
                curr = self.get_block_by_addr(succ_block.get_offsets()[0])
                if [parent, curr] in self.edges:
                    parent.successors.append(self.cache[succ_offset])
                    continue

                if curr.visited:
                    continue
                # if its a call instruction we must also process the
                # return edges
                if curr_block.lines[-1].name in ["CALL"]:
                    self.handle_calls(curr_block)

                # traverse
                curr_block = succ_block
                # print("==========361===========")
                # print(curr_block)
                # print("==========361===========")
                self.build_graph(curr_block, parent, curr)

        # if it has successors and it has afl id
        else:
            curr.block_id = afl_blockid
            if parent != curr:
                parent.successors.append(curr)
                self.edges.append([parent, curr])
            parent = curr
            for successor in self.asmcfg.successors_iter(curr_block.loc_key):

                # detect loops
                succ_offset = self.context.get_location_offset(successor)
                succ_block = self.asmcfg.loc_key_to_block(successor)
                curr = self.get_block_by_addr(succ_block.get_offsets()[0])
                if [parent, curr] in self.edges:
                    parent.successors.append(self.cache[succ_offset])
                    continue

                if curr.visited:
                    continue

                if curr_block.lines[-1].name in ["CALL"]:
                    self.handle_calls(curr_block)

                curr_block = succ_block
                # print("==========387===========")
                # print(curr_block)
                # print("==========387===========")
                self.build_graph(curr_block, parent, curr)

    def process_pending_edges(self):
        # process the pending edges
        for i in self.pending_edges:
            e0_offset = self.context.cont.loc_db.get_location_offset(i[0])
            e1_offset = self.context.cont.loc_db.get_location_offset(i[1])
            e0_afl_block = self.get_block_by_addr(e0_offset)
            e1_afl_block = self.get_block_by_addr(e1_offset)
            e0_afl_block.block_id = self.context.get_afl_blockid(i[0])
            e1_afl_block.block_id = self.context.get_afl_blockid(i[1])
            self.get_hit_for_edge([e0_afl_block, e1_afl_block])

    def get_blocks(self):
        return list(self.cache.values())

    def get_edges(self):
        edges = []
        [edges.append(x) for x in self.edges if x not in edges]
        return edges

    def get_hits(self):
        with open(self.context.bitmap, "rb") as file:
            bitmap = file.read()
            file.close()

        for edge in self.get_edges():
            b0 = edge[0]
            b1 = edge[1]

            idx = (b0.block_id >> 1) ^ b1.block_id
            if bitmap[idx] != 0xFF:
                b0.hit = True
                b1.hit = True

    def get_hit_for_edge(self, edge):
        with open(self.context.bitmap, "rb") as file:
            bitmap = file.read()
            file.close()

        b0 = edge[0]
        b1 = edge[1]

        idx = (b0.block_id >> 1) ^ b1.block_id
        if bitmap[idx] != 0xFF:
            b0.hit = True
            b1.hit = True

    def dump(self, filename):
        blocks = self.get_blocks()
        with open(filename, "w") as file:
            for block in blocks:
                if block.hit:
                    file.write("0x%.16x\n" % block.address)
            file.close()

    def get_dot(self, filename):
        """Render dot graph with HTML"""

        out = ["digraph afl_graph {"]

        # Generate basic nodes
        out_nodes = []
        nodes = list(self.cache.values())
        for node in nodes:
            if node.block_id == 0:
                continue
            out_node = '%d [\nshape="Mrecord" fontname="Courier New"' % (
                node.address & 0xFFFF
            )
            out_node += 'label =<<table border="0" cellborder="0" cellpadding="3">'

            out_render = (
                '<tr><td align="center" colspan="2" bgcolor="grey">0x%x</td></tr>'
                % (node.address)
                + '<tr><td align="left">Block ID:      0x%x</td></tr>' % (node.block_id)
                + '<tr><td align="left">Address :      0x%x</td></tr>' % (node.address)
                + '<tr><td align="left">Hit     :      %s</td></tr>'
                % (["False", "True"][int(node.hit)])
            )

            out_node += out_render + "</table>> ];"
            out_nodes.append(out_node)

            out += out_nodes

        # Generate Links
        for edge in self.get_edges():
            out.append(
                '%d -> %d [color="limegreen"];'
                % (edge[0].address & 0xFFFF, edge[1].address & 0xFFFF)
            )
        out.append("}")
        with open(filename, "w") as file:
            file.write("\n".join(out))
            file.close()
        return "\n".join(out)

    def get_block_by_addr(self, addr):
        if addr not in self.cache.keys():
            self.cache[addr] = AFLBlock(addr)
        return self.cache[addr]
