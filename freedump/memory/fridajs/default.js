function initConfig() {}

function readMemory(address, size) {
  try {
    if (ptr(address).isNull() == false) {
      return Memory.readByteArray(ptr(address), size);
    } else {
      return false;
    }
  } catch (e) {
    return false;
  }
}
