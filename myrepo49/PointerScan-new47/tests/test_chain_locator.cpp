#include "chainer/chain_locator.hpp"
#include <cassert>
#include <iostream>
int main() {
  chainer::locator::ParsedChain c; std::string e;
  assert(chainer::locator::parse_chain("libunity.so:bss+0x72448+0x1508+0x1398+0x280+0x874", c, e));
  assert(c.module == "libunity.so" && c.bss && c.offsets.size() == 5);
  assert(c.offsets[0] == 0x72448 && c.offsets[4] == 0x874);
  assert(chainer::locator::parse_chain("libunity.so:bss[1] + 0x72448 -> + 0x1508 -> + 0x1398 -> + 0x280 -> + 0x874", c, e));
  assert(c.module == "libunity.so" && c.bss && c.occurrence == 1 && c.offsets.size() == 5);
  assert(chainer::locator::parse_chain("libunity.so[2] + 0x100 -> + 0x20", c, e));
  assert(c.module == "libunity.so" && !c.bss && c.occurrence == 2 && c.offsets.size() == 2);
  std::cout << "chain parser tests passed\n";
}
