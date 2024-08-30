rpc.exports = {
    initConfig: initConfig,
    enumerateRanges: function (prot) {
        return Process.enumerateRangesSync(prot);
    },
    readMemory: readMemory,
};
