// Got from https://github.com/DoranekoSystems/frida-ceserver and add some modification

var process_vm_readv;
var process_vm_writev;
var LZ4_compress_default;
var LZ4_compressBound;
var LZ4_compress_fast;

var g_Buffer;
var g_dstBuffer;
var g_Task;
var g_Mutex = true;

//Up to 1 threads can be handled simultaneously
const g_bufferSize = 1024 * 1024 * 64;
const g_maxThread = 1;
g_Buffer = Memory.alloc(g_bufferSize * g_maxThread);
g_dstBuffer = Memory.alloc(g_bufferSize * g_maxThread);
const PS = Process.pointerSize;

var loop_count = 0;

function initConfig() {
  Module.load("liblz4.so");

  var LZ4_compress_defaultPtr = Module.findExportByName(
    "liblz4.so",
    "LZ4_compress_default",
  );
  LZ4_compress_default = new NativeFunction(LZ4_compress_defaultPtr, "int", [
    "pointer",
    "pointer",
    "int",
    "int",
  ]);
  var LZ4_compress_fastPtr = Module.findExportByName(
    "liblz4.so",
    "LZ4_compress_fast",
  );
  LZ4_compress_fast = new NativeFunction(LZ4_compress_fastPtr, "int", [
    "pointer",
    "pointer",
    "int",
    "int",
    "int",
  ]);
  var LZ4_compressBoundPtr = Module.findExportByName(
    "liblz4.so",
    "LZ4_compressBound",
  );
  LZ4_compressBound = new NativeFunction(LZ4_compressBoundPtr, "int", ["int"]);
  var process_vm_readvPtr = Module.findExportByName(null, "process_vm_readv");
  process_vm_readv = new NativeFunction(process_vm_readvPtr, "int", [
    "int",
    "pointer",
    "int",
    "pointer",
    "int",
    "int",
  ]);
}

function readMemory(address, size) {
  loop_count++;
  var start_offset = (loop_count % g_maxThread) * g_bufferSize;

  var local = Memory.alloc(32);
  var remote = Memory.alloc(32);

  local.writePointer(g_Buffer.add(start_offset));
  local.add(PS).writeUInt(size);
  remote.writePointer(ptr(address));
  remote.add(PS).writeUInt(size);

  var size_out = process_vm_readv(Process.id, local, 1, remote, 1, 0);
  if (size_out == -1) {
    return false;
  } else {
    var dstCapacity = LZ4_compressBound(size_out);
    var compress_size = LZ4_compress_default(
      g_Buffer.add(start_offset),
      g_dstBuffer.add(start_offset),
      size_out,
      dstCapacity,
    );
    var ret = ArrayBuffer.wrap(
      g_dstBuffer.add(start_offset),
      compress_size + 4,
    );
    g_dstBuffer.add(start_offset + compress_size).writeUInt(size_out);
    return ret;
  }
}
