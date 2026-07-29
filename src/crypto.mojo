"""AES, ChaCha20, and SHA-2 kernels exposed through a small C ABI."""

from std.builtin.globals import global_constant
from std.sys.info import simd_width_of
from std.sys.intrinsics import llvm_intrinsic

comptime BPtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]


@always_inline
def bp(address: Int) -> BPtr:
    return BPtr(unsafe_from_address=address)


@always_inline
def rotl32(value: UInt32, amount: UInt32) -> UInt32:
    return (value << amount) | (value >> (UInt32(32) - amount))


@always_inline
def rotr32(value: UInt32, amount: UInt32) -> UInt32:
    return (value >> amount) | (value << (UInt32(32) - amount))


@always_inline
def rotr64(value: UInt64, amount: UInt64) -> UInt64:
    return (value >> amount) | (value << (UInt64(64) - amount))


@always_inline
def load32_le(source: UnsafePointer[UInt8, _], offset: Int) -> UInt32:
    return (
        UInt32(source[offset])
        | (UInt32(source[offset + 1]) << 8)
        | (UInt32(source[offset + 2]) << 16)
        | (UInt32(source[offset + 3]) << 24)
    )


@always_inline
def load32_be(source: UnsafePointer[UInt8, _], offset: Int) -> UInt32:
    return (
        (UInt32(source[offset]) << 24)
        | (UInt32(source[offset + 1]) << 16)
        | (UInt32(source[offset + 2]) << 8)
        | UInt32(source[offset + 3])
    )


@always_inline
def load64_be(source: UnsafePointer[UInt8, _], offset: Int) -> UInt64:
    return (
        (UInt64(source[offset]) << 56)
        | (UInt64(source[offset + 1]) << 48)
        | (UInt64(source[offset + 2]) << 40)
        | (UInt64(source[offset + 3]) << 32)
        | (UInt64(source[offset + 4]) << 24)
        | (UInt64(source[offset + 5]) << 16)
        | (UInt64(source[offset + 6]) << 8)
        | UInt64(source[offset + 7])
    )


@always_inline
def store32_le[destination_origin: MutOrigin](
    destination: UnsafePointer[UInt8, destination_origin], offset: Int, value: UInt32
):
    destination[offset] = UInt8(value)
    destination[offset + 1] = UInt8(value >> 8)
    destination[offset + 2] = UInt8(value >> 16)
    destination[offset + 3] = UInt8(value >> 24)


@always_inline
def store32_be[destination_origin: MutOrigin](
    destination: UnsafePointer[UInt8, destination_origin], offset: Int, value: UInt32
):
    destination[offset] = UInt8(value >> 24)
    destination[offset + 1] = UInt8(value >> 16)
    destination[offset + 2] = UInt8(value >> 8)
    destination[offset + 3] = UInt8(value)


@always_inline
def store64_be[destination_origin: MutOrigin](
    destination: UnsafePointer[UInt8, destination_origin], offset: Int, value: UInt64
):
    destination[offset] = UInt8(value >> 56)
    destination[offset + 1] = UInt8(value >> 48)
    destination[offset + 2] = UInt8(value >> 40)
    destination[offset + 3] = UInt8(value >> 32)
    destination[offset + 4] = UInt8(value >> 24)
    destination[offset + 5] = UInt8(value >> 16)
    destination[offset + 6] = UInt8(value >> 8)
    destination[offset + 7] = UInt8(value)


@always_inline
def xor_bytes[
    source_origin: MutOrigin,
    mask_origin: MutOrigin,
    destination_origin: MutOrigin,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    mask: UnsafePointer[UInt8, mask_origin],
    mask_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    count: Int,
):
    comptime W = simd_width_of[DType.float64]()
    comptime BYTE_W = W * 8
    var i = 0
    while i + BYTE_W <= count:
        var wide_values = source.load[width=BYTE_W](source_offset + i)
        var wide_masks = mask.load[width=BYTE_W](mask_offset + i)
        destination.store(destination_offset + i, wide_values ^ wide_masks)
        i += BYTE_W
    while i + W <= count:
        var tail_values = source.load[width=W](source_offset + i)
        var tail_masks = mask.load[width=W](mask_offset + i)
        destination.store(destination_offset + i, tail_values ^ tail_masks)
        i += W
    while i < count:
        destination[destination_offset + i] = (
            source[source_offset + i] ^ mask[mask_offset + i]
        )
        i += 1


# AES -------------------------------------------------------------------------

@always_inline
def aes_sbox(index: UInt8) -> UInt8:
    comptime table: InlineArray[UInt8, 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]
    ref static_table = global_constant[table]()
    return static_table[Int(index)]


@always_inline
def aes_inv_sbox(index: UInt8) -> UInt8:
    comptime table: InlineArray[UInt8, 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ]
    ref static_table = global_constant[table]()
    return static_table[Int(index)]


@always_inline
def aes_xtime(value: UInt8) -> UInt8:
    return (value << 1) ^ (UInt8(0x1b) if (value & 0x80) != 0 else UInt8(0))


@always_inline
def aes_mul(a: UInt8, b: UInt8) -> UInt8:
    var x = a
    var y = b
    var result = UInt8(0)
    for _ in range(8):
        if (y & 1) != 0:
            result ^= x
        x = aes_xtime(x)
        y >>= 1
    return result


def aes_expand_key[key_origin: MutOrigin, expanded_origin: MutOrigin](
    key: UnsafePointer[UInt8, key_origin],
    key_length: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
) -> Int:
    var rounds = key_length // 4 + 6
    var total = 16 * (rounds + 1)
    for i in range(key_length):
        expanded[i] = key[i]
    var generated = key_length
    var rcon = UInt8(1)
    var temp = InlineArray[UInt8, 4](fill=0)
    while generated < total:
        for j in range(4):
            temp[j] = expanded[generated - 4 + j]
        if generated % key_length == 0:
            var first = temp[0]
            temp[0] = aes_sbox(temp[1])
            temp[1] = aes_sbox(temp[2])
            temp[2] = aes_sbox(temp[3])
            temp[3] = aes_sbox(first)
            temp[0] ^= rcon
            rcon = aes_xtime(rcon)
        elif key_length == 32 and generated % key_length == 16:
            for j in range(4):
                temp[j] = aes_sbox(temp[j])
        for j in range(4):
            expanded[generated] = expanded[generated - key_length] ^ temp[j]
            generated += 1
    return rounds


@always_inline
def aes_add_round_key[state_origin: MutOrigin, expanded_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin],
    expanded: UnsafePointer[UInt8, expanded_origin],
    offset: Int,
):
    comptime W = simd_width_of[DType.float64]()
    var state_words = state.bitcast[UInt32]()
    var key_words = (expanded + offset).bitcast[UInt32]()
    state_words.store(
        0,
        state_words.load[width=W](0) ^ key_words.load[width=W](0),
    )


@always_inline
def aes_shift_rows[state_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin]
):
    var t = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = t
    t = state[2]
    var u = state[6]
    state[2] = state[10]
    state[6] = state[14]
    state[10] = t
    state[14] = u
    t = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = t


@always_inline
def aes_inv_shift_rows[state_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin]
):
    var t = state[13]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = state[1]
    state[1] = t
    t = state[2]
    var u = state[6]
    state[2] = state[10]
    state[6] = state[14]
    state[10] = t
    state[14] = u
    t = state[3]
    state[3] = state[7]
    state[7] = state[11]
    state[11] = state[15]
    state[15] = t


@always_inline
def aes_mix_columns[state_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin]
):
    for column in range(4):
        var i = column * 4
        var a = state[i]
        var b = state[i + 1]
        var c = state[i + 2]
        var d = state[i + 3]
        var all = a ^ b ^ c ^ d
        state[i] = a ^ all ^ aes_xtime(a ^ b)
        state[i + 1] = b ^ all ^ aes_xtime(b ^ c)
        state[i + 2] = c ^ all ^ aes_xtime(c ^ d)
        state[i + 3] = d ^ all ^ aes_xtime(d ^ a)


@always_inline
def aes_inv_mix_columns[state_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin]
):
    for column in range(4):
        var i = column * 4
        var a = state[i]
        var b = state[i + 1]
        var c = state[i + 2]
        var d = state[i + 3]
        state[i] = aes_mul(a, 14) ^ aes_mul(b, 11) ^ aes_mul(c, 13) ^ aes_mul(d, 9)
        state[i + 1] = aes_mul(a, 9) ^ aes_mul(b, 14) ^ aes_mul(c, 11) ^ aes_mul(d, 13)
        state[i + 2] = aes_mul(a, 13) ^ aes_mul(b, 9) ^ aes_mul(c, 14) ^ aes_mul(d, 11)
        state[i + 3] = aes_mul(a, 11) ^ aes_mul(b, 13) ^ aes_mul(c, 9) ^ aes_mul(d, 14)


def aes_encrypt_block[
    source_origin: MutOrigin,
    destination_origin: MutOrigin,
    expanded_origin: MutOrigin,
    rounds: Int,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
):
    var state = InlineArray[UInt8, 16](fill=0)
    var state_ptr = UnsafePointer(to=state[0])
    for i in range(16):
        state[i] = source[source_offset + i]
    aes_add_round_key(state_ptr, expanded, 0)
    comptime for round_index in range(1, rounds):
        for i in range(16):
            state[i] = aes_sbox(state[i])
        aes_shift_rows(state_ptr)
        aes_mix_columns(state_ptr)
        aes_add_round_key(state_ptr, expanded, round_index * 16)
    for i in range(16):
        state[i] = aes_sbox(state[i])
    aes_shift_rows(state_ptr)
    aes_add_round_key(state_ptr, expanded, rounds * 16)
    for i in range(16):
        destination[destination_offset + i] = state[i]


def aes_decrypt_block[
    source_origin: MutOrigin,
    destination_origin: MutOrigin,
    expanded_origin: MutOrigin,
    rounds: Int,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
):
    var state = InlineArray[UInt8, 16](fill=0)
    var state_ptr = UnsafePointer(to=state[0])
    for i in range(16):
        state[i] = source[source_offset + i]
    aes_add_round_key(state_ptr, expanded, rounds * 16)
    comptime for round_index in range(rounds - 1, 0, -1):
        aes_inv_shift_rows(state_ptr)
        for i in range(16):
            state[i] = aes_inv_sbox(state[i])
        aes_add_round_key(state_ptr, expanded, round_index * 16)
        aes_inv_mix_columns(state_ptr)
    aes_inv_shift_rows(state_ptr)
    for i in range(16):
        state[i] = aes_inv_sbox(state[i])
    aes_add_round_key(state_ptr, expanded, 0)
    for i in range(16):
        destination[destination_offset + i] = state[i]


@always_inline
def aes_encrypt_block_aesni[
    source_origin: MutOrigin,
    destination_origin: MutOrigin,
    expanded_origin: MutOrigin,
    rounds: Int,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
):
    var state = (
        (source + source_offset).bitcast[UInt64]().load[width=2](0)
        ^ expanded.bitcast[UInt64]().load[width=2](0)
    )
    comptime for round_index in range(1, rounds):
        var round_key = (
            expanded + round_index * 16
        ).bitcast[UInt64]().load[width=2](0)
        state = llvm_intrinsic[
            "llvm.x86.aesni.aesenc", SIMD[DType.uint64, 2]
        ](state, round_key)
    var final_key = (
        expanded + rounds * 16
    ).bitcast[UInt64]().load[width=2](0)
    state = llvm_intrinsic[
        "llvm.x86.aesni.aesenclast", SIMD[DType.uint64, 2]
    ](state, final_key)
    (destination + destination_offset).bitcast[UInt64]().store(0, state)


@always_inline
def aes_decrypt_block_aesni[
    source_origin: MutOrigin,
    destination_origin: MutOrigin,
    expanded_origin: MutOrigin,
    rounds: Int,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
):
    var state = (
        (source + source_offset).bitcast[UInt64]().load[width=2](0)
        ^ (expanded + rounds * 16).bitcast[UInt64]().load[width=2](0)
    )
    comptime for round_index in range(rounds - 1, 0, -1):
        var round_key = (
            expanded + round_index * 16
        ).bitcast[UInt64]().load[width=2](0)
        round_key = llvm_intrinsic[
            "llvm.x86.aesni.aesimc", SIMD[DType.uint64, 2]
        ](round_key)
        state = llvm_intrinsic[
            "llvm.x86.aesni.aesdec", SIMD[DType.uint64, 2]
        ](state, round_key)
    var final_key = expanded.bitcast[UInt64]().load[width=2](0)
    state = llvm_intrinsic[
        "llvm.x86.aesni.aesdeclast", SIMD[DType.uint64, 2]
    ](state, final_key)
    (destination + destination_offset).bitcast[UInt64]().store(0, state)


@always_inline
def aes_encrypt_block_dispatch[
    source_origin: MutOrigin,
    destination_origin: MutOrigin,
    expanded_origin: MutOrigin,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
    rounds: Int,
    use_aesni: Int,
):
    if use_aesni != 0:
        if rounds == 10:
            aes_encrypt_block_aesni[rounds=10](
                source, source_offset, destination, destination_offset, expanded
            )
        elif rounds == 12:
            aes_encrypt_block_aesni[rounds=12](
                source, source_offset, destination, destination_offset, expanded
            )
        else:
            aes_encrypt_block_aesni[rounds=14](
                source, source_offset, destination, destination_offset, expanded
            )
    elif rounds == 10:
        aes_encrypt_block[rounds=10](
            source, source_offset, destination, destination_offset, expanded
        )
    elif rounds == 12:
        aes_encrypt_block[rounds=12](
            source, source_offset, destination, destination_offset, expanded
        )
    else:
        aes_encrypt_block[rounds=14](
            source, source_offset, destination, destination_offset, expanded
        )


@always_inline
def aes_decrypt_block_dispatch[
    source_origin: MutOrigin,
    destination_origin: MutOrigin,
    expanded_origin: MutOrigin,
](
    source: UnsafePointer[UInt8, source_origin],
    source_offset: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_offset: Int,
    expanded: UnsafePointer[UInt8, expanded_origin],
    rounds: Int,
    use_aesni: Int,
):
    if use_aesni != 0:
        if rounds == 10:
            aes_decrypt_block_aesni[rounds=10](
                source, source_offset, destination, destination_offset, expanded
            )
        elif rounds == 12:
            aes_decrypt_block_aesni[rounds=12](
                source, source_offset, destination, destination_offset, expanded
            )
        else:
            aes_decrypt_block_aesni[rounds=14](
                source, source_offset, destination, destination_offset, expanded
            )
    elif rounds == 10:
        aes_decrypt_block[rounds=10](
            source, source_offset, destination, destination_offset, expanded
        )
    elif rounds == 12:
        aes_decrypt_block[rounds=12](
            source, source_offset, destination, destination_offset, expanded
        )
    else:
        aes_decrypt_block[rounds=14](
            source, source_offset, destination, destination_offset, expanded
        )


@export("mpc_aes_ecb")
def mpc_aes_ecb(source_address: Int, destination_address: Int, size: Int, key_address: Int, key_length: Int, decrypt: Int, use_aesni: Int) abi("C") -> Int:
    if size < 0 or source_address == 0 or destination_address == 0 or key_address == 0:
        return -3
    if key_length != 16 and key_length != 24 and key_length != 32:
        return -1
    if size % 16 != 0:
        return -2
    var source = bp(source_address)
    var destination = bp(destination_address)
    var key = bp(key_address)
    var expanded = InlineArray[UInt8, 240](fill=0)
    var expanded_ptr = UnsafePointer(to=expanded[0])
    var rounds = aes_expand_key(key, key_length, expanded_ptr)
    var offset = 0
    while offset < size:
        if decrypt != 0:
            aes_decrypt_block_dispatch(
                source, offset, destination, offset, expanded_ptr, rounds, use_aesni
            )
        else:
            aes_encrypt_block_dispatch(
                source, offset, destination, offset, expanded_ptr, rounds, use_aesni
            )
        offset += 16
    return 0


@export("mpc_aes_cbc")
def mpc_aes_cbc(source_address: Int, destination_address: Int, size: Int, key_address: Int, key_length: Int, iv_address: Int, decrypt: Int, use_aesni: Int) abi("C") -> Int:
    if size < 0 or source_address == 0 or destination_address == 0 or key_address == 0 or iv_address == 0:
        return -3
    if key_length != 16 and key_length != 24 and key_length != 32:
        return -1
    if size % 16 != 0:
        return -2
    var source = bp(source_address)
    var destination = bp(destination_address)
    var key = bp(key_address)
    var iv = bp(iv_address)
    var expanded = InlineArray[UInt8, 240](fill=0)
    var expanded_ptr = UnsafePointer(to=expanded[0])
    var rounds = aes_expand_key(key, key_length, expanded_ptr)
    var block = InlineArray[UInt8, 16](fill=0)
    var block_ptr = UnsafePointer(to=block[0])
    var offset = 0
    while offset < size:
        if decrypt != 0:
            for i in range(16):
                block[i] = source[offset + i]
            aes_decrypt_block_dispatch(
                source, offset, destination, offset, expanded_ptr, rounds, use_aesni
            )
            xor_bytes(destination, offset, iv, 0, destination, offset, 16)
            for i in range(16):
                iv[i] = block[i]
        else:
            xor_bytes(source, offset, iv, 0, block_ptr, 0, 16)
            aes_encrypt_block_dispatch(
                block_ptr, 0, destination, offset, expanded_ptr, rounds, use_aesni
            )
            for i in range(16):
                iv[i] = destination[offset + i]
        offset += 16
    return 0


@always_inline
def aes_increment_counter[counter_origin: MutOrigin](
    counter: UnsafePointer[UInt8, counter_origin],
    offset: Int,
    length: Int,
    little_endian: Int,
):
    if little_endian != 0:
        for i in range(length):
            var position = offset + i
            counter[position] += 1
            if counter[position] != 0:
                break
    else:
        for i in range(length):
            var position = offset + length - 1 - i
            counter[position] += 1
            if counter[position] != 0:
                break


@export("mpc_aes_ctr")
def mpc_aes_ctr(source_address: Int, destination_address: Int, size: Int, key_address: Int, key_length: Int, counter_address: Int, skip: Int, counter_offset: Int, counter_length: Int, little_endian: Int, use_aesni: Int) abi("C") -> Int:
    if size < 0 or source_address == 0 or destination_address == 0 or key_address == 0 or counter_address == 0:
        return -3
    if key_length != 16 and key_length != 24 and key_length != 32:
        return -1
    if skip < 0 or skip >= 16 or counter_offset < 0 or counter_length <= 0 or counter_offset + counter_length > 16:
        return -2
    var source = bp(source_address)
    var destination = bp(destination_address)
    var key = bp(key_address)
    var initial_counter = bp(counter_address)
    var expanded = InlineArray[UInt8, 240](fill=0)
    var expanded_ptr = UnsafePointer(to=expanded[0])
    var rounds = aes_expand_key(key, key_length, expanded_ptr)
    var counter = InlineArray[UInt8, 16](fill=0)
    var counter_ptr = UnsafePointer(to=counter[0])
    var stream = InlineArray[UInt8, 16](fill=0)
    var stream_ptr = UnsafePointer(to=stream[0])
    for i in range(16):
        counter[i] = initial_counter[i]
    var position = 0
    var stream_position = skip
    while position < size:
        aes_encrypt_block_dispatch(
            counter_ptr, 0, stream_ptr, 0, expanded_ptr, rounds, use_aesni
        )
        var count = 16 - stream_position
        if count > size - position:
            count = size - position
        xor_bytes(
            source,
            position,
            stream_ptr,
            stream_position,
            destination,
            position,
            count,
        )
        position += count
        stream_position = 0
        aes_increment_counter(counter_ptr, counter_offset, counter_length, little_endian)
    return 0


# ChaCha20 --------------------------------------------------------------------

@always_inline
def chacha_quarter[state_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin], a: Int, b: Int, c: Int, d: Int
):
    var words = state.bitcast[UInt32]()
    words[a] += words[b]
    words[d] ^= words[a]
    words[d] = rotl32(words[d], 16)
    words[c] += words[d]
    words[b] ^= words[c]
    words[b] = rotl32(words[b], 12)
    words[a] += words[b]
    words[d] ^= words[a]
    words[d] = rotl32(words[d], 8)
    words[c] += words[d]
    words[b] ^= words[c]
    words[b] = rotl32(words[b], 7)


def chacha_rounds[state_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin]
):
    comptime for _ in range(10):
        chacha_quarter(state, 0, 4, 8, 12)
        chacha_quarter(state, 1, 5, 9, 13)
        chacha_quarter(state, 2, 6, 10, 14)
        chacha_quarter(state, 3, 7, 11, 15)
        chacha_quarter(state, 0, 5, 10, 15)
        chacha_quarter(state, 1, 6, 11, 12)
        chacha_quarter(state, 2, 7, 8, 13)
        chacha_quarter(state, 3, 4, 9, 14)


def hchacha20[
    key_origin: MutOrigin,
    nonce_origin: MutOrigin,
    subkey_origin: MutOrigin,
](
    key: UnsafePointer[UInt8, key_origin],
    nonce: UnsafePointer[UInt8, nonce_origin],
    subkey: UnsafePointer[UInt8, subkey_origin],
):
    var state = InlineArray[UInt32, 16](fill=0)
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574
    for i in range(8):
        state[4 + i] = load32_le(key, i * 4)
    for i in range(4):
        state[12 + i] = load32_le(nonce, i * 4)
    chacha_rounds(UnsafePointer(to=state[0]).bitcast[UInt8]())
    store32_le(subkey, 0, state[0])
    store32_le(subkey, 4, state[1])
    store32_le(subkey, 8, state[2])
    store32_le(subkey, 12, state[3])
    store32_le(subkey, 16, state[12])
    store32_le(subkey, 20, state[13])
    store32_le(subkey, 24, state[14])
    store32_le(subkey, 28, state[15])


def chacha_block[
    key_origin: MutOrigin,
    nonce_origin: MutOrigin,
    destination_origin: MutOrigin,
](
    key: UnsafePointer[UInt8, key_origin],
    nonce: UnsafePointer[UInt8, nonce_origin],
    nonce_length: Int,
    block_counter: UInt64,
    destination: UnsafePointer[UInt8, destination_origin],
):
    var derived_key = InlineArray[UInt8, 32](fill=0)
    var derived_ptr = UnsafePointer(to=derived_key[0])
    if nonce_length == 24:
        hchacha20(key, nonce, derived_ptr)

    var initial = InlineArray[UInt32, 16](fill=0)
    initial[0] = 0x61707865
    initial[1] = 0x3320646e
    initial[2] = 0x79622d32
    initial[3] = 0x6b206574
    for i in range(8):
        if nonce_length == 24:
            initial[4 + i] = load32_le(derived_ptr, i * 4)
        else:
            initial[4 + i] = load32_le(key, i * 4)
    if nonce_length == 8:
        initial[12] = UInt32(block_counter)
        initial[13] = UInt32(block_counter >> 32)
        initial[14] = load32_le(nonce, 0)
        initial[15] = load32_le(nonce, 4)
    elif nonce_length == 12:
        initial[12] = UInt32(block_counter)
        initial[13] = load32_le(nonce, 0)
        initial[14] = load32_le(nonce, 4)
        initial[15] = load32_le(nonce, 8)
    else:
        initial[12] = UInt32(block_counter)
        initial[13] = 0
        initial[14] = load32_le(nonce, 16)
        initial[15] = load32_le(nonce, 20)
    var working = InlineArray[UInt32, 16](fill=0)
    for i in range(16):
        working[i] = initial[i]
    chacha_rounds(UnsafePointer(to=working[0]).bitcast[UInt8]())
    for i in range(16):
        store32_le(destination, i * 4, working[i] + initial[i])


@export("mpc_chacha20")
def mpc_chacha20(source_address: Int, destination_address: Int, size: Int, key_address: Int, key_length: Int, nonce_address: Int, nonce_length: Int, byte_position: UInt64) abi("C") -> Int:
    if size < 0 or source_address == 0 or destination_address == 0 or key_address == 0 or nonce_address == 0:
        return -3
    if key_length != 32:
        return -2
    if nonce_length != 8 and nonce_length != 12 and nonce_length != 24:
        return -1
    var source = bp(source_address)
    var destination = bp(destination_address)
    var key = bp(key_address)
    var nonce = bp(nonce_address)
    var stream = InlineArray[UInt8, 64](fill=0)
    var stream_ptr = UnsafePointer(to=stream[0])
    var block_counter = byte_position // 64
    var skip = Int(byte_position % 64)
    var position = 0
    while position < size:
        chacha_block(key, nonce, nonce_length, block_counter, stream_ptr)
        var count = 64 - skip
        if count > size - position:
            count = size - position
        xor_bytes(
            source,
            position,
            stream_ptr,
            skip,
            destination,
            position,
            count,
        )
        position += count
        block_counter += 1
        skip = 0
    return 0


# SHA-2 -----------------------------------------------------------------------

def sha256_compress[state_origin: MutOrigin, block_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin],
    block: UnsafePointer[UInt8, block_origin],
):
    var words = state.bitcast[UInt32]()
    var schedule = InlineArray[UInt32, 16](fill=0)
    for i in range(16):
        schedule[i] = load32_be(block, i * 4)
    comptime constants: InlineArray[UInt32, 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]
    ref round_constants = global_constant[constants]()
    var a = words[0]
    var b = words[1]
    var c = words[2]
    var d = words[3]
    var e = words[4]
    var f = words[5]
    var g = words[6]
    var h = words[7]
    comptime for i in range(64):
        comptime if i >= 16:
            var x = schedule[(i - 15) % 16]
            var y = schedule[(i - 2) % 16]
            var s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)
            var s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10)
            schedule[i % 16] = (
                schedule[(i - 16) % 16]
                + s0
                + schedule[(i - 7) % 16]
                + s1
            )
        var sum1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
        var choice = (e & f) ^ ((~e) & g)
        var t1 = h + sum1 + choice + round_constants[i] + schedule[i % 16]
        var sum0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
        var majority = (a & b) ^ (a & c) ^ (b & c)
        var t2 = sum0 + majority
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    words[0] += a
    words[1] += b
    words[2] += c
    words[3] += d
    words[4] += e
    words[5] += f
    words[6] += g
    words[7] += h


@export("mpc_sha256")
def mpc_sha256(source_address: Int, size: Int, destination_address: Int, sha224: Int) abi("C") -> Int:
    if size < 0 or source_address == 0 or destination_address == 0:
        return -1
    var source = bp(source_address)
    var destination = bp(destination_address)
    var state = InlineArray[UInt32, 8](fill=0)
    if sha224 != 0:
        state[0] = 0xc1059ed8
        state[1] = 0x367cd507
        state[2] = 0x3070dd17
        state[3] = 0xf70e5939
        state[4] = 0xffc00b31
        state[5] = 0x68581511
        state[6] = 0x64f98fa7
        state[7] = 0xbefa4fa4
    else:
        state[0] = 0x6a09e667
        state[1] = 0xbb67ae85
        state[2] = 0x3c6ef372
        state[3] = 0xa54ff53a
        state[4] = 0x510e527f
        state[5] = 0x9b05688c
        state[6] = 0x1f83d9ab
        state[7] = 0x5be0cd19
    var state_ptr = UnsafePointer(to=state[0]).bitcast[UInt8]()
    var offset = 0
    while offset + 64 <= size:
        sha256_compress(state_ptr, source + offset)
        offset += 64
    var final_blocks = InlineArray[UInt8, 128](fill=0)
    var final_ptr = UnsafePointer(to=final_blocks[0])
    var remainder = size - offset
    for i in range(remainder):
        final_blocks[i] = source[offset + i]
    final_blocks[remainder] = 0x80
    var final_size = 64 if remainder < 56 else 128
    var bit_length = UInt64(size) * 8
    store64_be(final_ptr, final_size - 8, bit_length)
    sha256_compress(state_ptr, final_ptr)
    if final_size == 128:
        sha256_compress(state_ptr, final_ptr + 64)
    var count = 7 if sha224 != 0 else 8
    for i in range(count):
        store32_be(destination, i * 4, state[i])
    return 0


def sha512_compress[state_origin: MutOrigin, block_origin: MutOrigin](
    state: UnsafePointer[UInt8, state_origin],
    block: UnsafePointer[UInt8, block_origin],
):
    var words = state.bitcast[UInt64]()
    var schedule = InlineArray[UInt64, 16](fill=0)
    for i in range(16):
        schedule[i] = load64_be(block, i * 8)
    comptime constants: InlineArray[UInt64, 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
        0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210,
        0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910,
        0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60,
        0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9,
        0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]
    ref round_constants = global_constant[constants]()
    var a = words[0]
    var b = words[1]
    var c = words[2]
    var d = words[3]
    var e = words[4]
    var f = words[5]
    var g = words[6]
    var h = words[7]
    comptime for i in range(80):
        comptime if i >= 16:
            var x = schedule[(i - 15) % 16]
            var y = schedule[(i - 2) % 16]
            var s0 = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)
            var s1 = rotr64(y, 19) ^ rotr64(y, 61) ^ (y >> 6)
            schedule[i % 16] = (
                schedule[(i - 16) % 16]
                + s0
                + schedule[(i - 7) % 16]
                + s1
            )
        var sum1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
        var choice = (e & f) ^ ((~e) & g)
        var t1 = h + sum1 + choice + round_constants[i] + schedule[i % 16]
        var sum0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
        var majority = (a & b) ^ (a & c) ^ (b & c)
        var t2 = sum0 + majority
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    words[0] += a
    words[1] += b
    words[2] += c
    words[3] += d
    words[4] += e
    words[5] += f
    words[6] += g
    words[7] += h


@export("mpc_sha512")
def mpc_sha512(source_address: Int, size: Int, destination_address: Int, sha384: Int) abi("C") -> Int:
    if size < 0 or source_address == 0 or destination_address == 0:
        return -1
    var source = bp(source_address)
    var destination = bp(destination_address)
    var state = InlineArray[UInt64, 8](fill=0)
    if sha384 != 0:
        state[0] = 0xcbbb9d5dc1059ed8
        state[1] = 0x629a292a367cd507
        state[2] = 0x9159015a3070dd17
        state[3] = 0x152fecd8f70e5939
        state[4] = 0x67332667ffc00b31
        state[5] = 0x8eb44a8768581511
        state[6] = 0xdb0c2e0d64f98fa7
        state[7] = 0x47b5481dbefa4fa4
    else:
        state[0] = 0x6a09e667f3bcc908
        state[1] = 0xbb67ae8584caa73b
        state[2] = 0x3c6ef372fe94f82b
        state[3] = 0xa54ff53a5f1d36f1
        state[4] = 0x510e527fade682d1
        state[5] = 0x9b05688c2b3e6c1f
        state[6] = 0x1f83d9abfb41bd6b
        state[7] = 0x5be0cd19137e2179
    var state_ptr = UnsafePointer(to=state[0]).bitcast[UInt8]()
    var offset = 0
    while offset + 128 <= size:
        sha512_compress(state_ptr, source + offset)
        offset += 128
    var final_blocks = InlineArray[UInt8, 256](fill=0)
    var final_ptr = UnsafePointer(to=final_blocks[0])
    var remainder = size - offset
    for i in range(remainder):
        final_blocks[i] = source[offset + i]
    final_blocks[remainder] = 0x80
    var final_size = 128 if remainder < 112 else 256
    var bit_length = UInt64(size) * 8
    store64_be(final_ptr, final_size - 16, 0)
    store64_be(final_ptr, final_size - 8, bit_length)
    sha512_compress(state_ptr, final_ptr)
    if final_size == 256:
        sha512_compress(state_ptr, final_ptr + 128)
    var count = 6 if sha384 != 0 else 8
    for i in range(count):
        store64_be(destination, i * 8, state[i])
    return 0
