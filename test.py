'''
    This file is part of AFL-Cast.

    AFL-Cast is free software: you can redistribute it and/or modify it under the terms of the 
    GNU General Public License as published by the Free Software Foundation, either version 3 
    of the License, or (at your option) any later version.

    AFL-Cast is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with AFL-Cast. 
    If not, see <https://www.gnu.org/licenses/>. 

'''

from AFLGraph import AFL

def test_2():
    afl = AFL(
        "test/afl2/test2",
        "test/afl2/fuzz_bitmap2",
        "main",
        True,
        ["__afl_maybe_log"],
    )
    graph = afl.get_afl_graph()
    graph.get_hits()

    def test_12c3():
        block = graph.get_block_by_addr(0x12C3)
        assert block.hit is True

    def test_11c0():
        block = graph.get_block_by_addr(0x11C0)
        assert block.hit is True

    def test_1320():
        block = graph.get_block_by_addr(0x1320)
        assert block.hit is True

    def test_1367():
        block = graph.get_block_by_addr(0x1367)
        assert block.hit is False

    def test_13ad():
        block = graph.get_block_by_addr(0x13AD)
        assert block.hit is True

    def test_127f():
        block = graph.get_block_by_addr(0x127F)
        assert block.hit is True

    def test_123b():
        block = graph.get_block_by_addr(0x123B)
        assert block.hit is False

    test_12c3()
    test_11c0()
    test_1320()
    test_1367()
    test_13ad()
    test_127f()
    test_123b()


def test_4():
    afl = AFL(
        "test/afl3/test4", "test/afl3/fuzz_bitmap4", "main", True, ["__afl_maybe_log"]
    )
    graph = afl.get_afl_graph()
    graph.get_hits()

    def test_1333():
        block = graph.get_block_by_addr(0x1333)
        assert block.hit is True

    def test_13b2():
        block = graph.get_block_by_addr(0x13B2)
        assert block.hit is True

    def test_14a5():
        block = graph.get_block_by_addr(0x14A5)
        assert block.hit is True

    def test_1589():
        block = graph.get_block_by_addr(0x1589)
        assert block.hit is True

    def test_140f():
        block = graph.get_block_by_addr(0x140F)
        assert block.hit is True

    def test_14f1():
        block = graph.get_block_by_addr(0x14F1)
        assert block.hit is True

    def test_15d5():
        block = graph.get_block_by_addr(0x15D5)
        assert block.hit is True

    def test_1459():
        block = graph.get_block_by_addr(0x1459)
        assert block.hit is True

    def test_153d():
        block = graph.get_block_by_addr(0x153D)
        assert block.hit is True

    def test_166a():
        block = graph.get_block_by_addr(0x166A)
        assert block.hit is True

    def test_16b0():
        block = graph.get_block_by_addr(0x16B0)
        assert block.hit is True

    def test_16b1():
        block = graph.get_block_by_addr(0x16B1)
        assert block.hit is True

    def test_12d0():
        block = graph.get_block_by_addr(0x12D0)
        assert block.hit is True

    def test_1700():
        block = graph.get_block_by_addr(0x1700)
        assert block.hit is False

    def test_173d():
        block = graph.get_block_by_addr(0x173D)
        assert block.hit is True

    test_1333()
    test_13b2()
    test_14a5()
    test_1589()
    test_140f()
    test_14f1()
    test_15d5()
    test_1459()
    test_153d()
    test_166a()
    test_16b0()
    test_16b1()
    test_12d0()
    test_1700()
    test_173d()
