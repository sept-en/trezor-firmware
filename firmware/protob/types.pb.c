/* Automatically generated nanopb constant definitions */
/* Generated by nanopb-0.2.9.3 */

#include "types.pb.h"

const uint32_t CoinType_address_type_default = 0u;
const uint32_t CoinType_address_type_p2sh_default = 5u;
const uint32_t CoinType_xpub_magic_default = 76067358u;
const uint32_t CoinType_xprv_magic_default = 76066276u;
const uint32_t TxInputType_sequence_default = 4294967295u;
const InputScriptType TxInputType_script_type_default = InputScriptType_SPENDADDRESS;
const uint32_t IdentityType_index_default = 0u;


const pb_field_t HDNodeType_fields[7] = {
    PB_FIELD2(  1, UINT32  , REQUIRED, STATIC  , FIRST, HDNodeType, depth, depth, 0),
    PB_FIELD2(  2, UINT32  , REQUIRED, STATIC  , OTHER, HDNodeType, fingerprint, depth, 0),
    PB_FIELD2(  3, UINT32  , REQUIRED, STATIC  , OTHER, HDNodeType, child_num, fingerprint, 0),
    PB_FIELD2(  4, BYTES   , REQUIRED, STATIC  , OTHER, HDNodeType, chain_code, child_num, 0),
    PB_FIELD2(  5, BYTES   , OPTIONAL, STATIC  , OTHER, HDNodeType, private_key, chain_code, 0),
    PB_FIELD2(  6, BYTES   , OPTIONAL, STATIC  , OTHER, HDNodeType, public_key, private_key, 0),
    PB_LAST_FIELD
};

const pb_field_t HDNodePathType_fields[3] = {
    PB_FIELD2(  1, MESSAGE , REQUIRED, STATIC  , FIRST, HDNodePathType, node, node, &HDNodeType_fields),
    PB_FIELD2(  2, UINT32  , REPEATED, STATIC  , OTHER, HDNodePathType, address_n, node, 0),
    PB_LAST_FIELD
};

const pb_field_t CoinType_fields[10] = {
    PB_FIELD2(  1, STRING  , OPTIONAL, STATIC  , FIRST, CoinType, coin_name, coin_name, 0),
    PB_FIELD2(  2, STRING  , OPTIONAL, STATIC  , OTHER, CoinType, coin_shortcut, coin_name, 0),
    PB_FIELD2(  3, UINT32  , OPTIONAL, STATIC  , OTHER, CoinType, address_type, coin_shortcut, &CoinType_address_type_default),
    PB_FIELD2(  4, UINT64  , OPTIONAL, STATIC  , OTHER, CoinType, maxfee_kb, address_type, 0),
    PB_FIELD2(  5, UINT32  , OPTIONAL, STATIC  , OTHER, CoinType, address_type_p2sh, maxfee_kb, &CoinType_address_type_p2sh_default),
    PB_FIELD2(  8, STRING  , OPTIONAL, STATIC  , OTHER, CoinType, signed_message_header, address_type_p2sh, 0),
    PB_FIELD2(  9, UINT32  , OPTIONAL, STATIC  , OTHER, CoinType, xpub_magic, signed_message_header, &CoinType_xpub_magic_default),
    PB_FIELD2( 10, UINT32  , OPTIONAL, STATIC  , OTHER, CoinType, xprv_magic, xpub_magic, &CoinType_xprv_magic_default),
    PB_FIELD2( 11, BOOL    , OPTIONAL, STATIC  , OTHER, CoinType, segwit, xprv_magic, 0),
    PB_LAST_FIELD
};

const pb_field_t MultisigRedeemScriptType_fields[4] = {
    PB_FIELD2(  1, MESSAGE , REPEATED, STATIC  , FIRST, MultisigRedeemScriptType, pubkeys, pubkeys, &HDNodePathType_fields),
    PB_FIELD2(  2, BYTES   , REPEATED, STATIC  , OTHER, MultisigRedeemScriptType, signatures, pubkeys, 0),
    PB_FIELD2(  3, UINT32  , OPTIONAL, STATIC  , OTHER, MultisigRedeemScriptType, m, signatures, 0),
    PB_LAST_FIELD
};

const pb_field_t TxInputType_fields[9] = {
    PB_FIELD2(  1, UINT32  , REPEATED, STATIC  , FIRST, TxInputType, address_n, address_n, 0),
    PB_FIELD2(  2, BYTES   , REQUIRED, STATIC  , OTHER, TxInputType, prev_hash, address_n, 0),
    PB_FIELD2(  3, UINT32  , REQUIRED, STATIC  , OTHER, TxInputType, prev_index, prev_hash, 0),
    PB_FIELD2(  4, BYTES   , OPTIONAL, STATIC  , OTHER, TxInputType, script_sig, prev_index, 0),
    PB_FIELD2(  5, UINT32  , OPTIONAL, STATIC  , OTHER, TxInputType, sequence, script_sig, &TxInputType_sequence_default),
    PB_FIELD2(  6, ENUM    , OPTIONAL, STATIC  , OTHER, TxInputType, script_type, sequence, &TxInputType_script_type_default),
    PB_FIELD2(  7, MESSAGE , OPTIONAL, STATIC  , OTHER, TxInputType, multisig, script_type, &MultisigRedeemScriptType_fields),
    PB_FIELD2(  8, UINT64  , OPTIONAL, STATIC  , OTHER, TxInputType, amount, multisig, 0),
    PB_LAST_FIELD
};

const pb_field_t TxOutputType_fields[7] = {
    PB_FIELD2(  1, STRING  , OPTIONAL, STATIC  , FIRST, TxOutputType, address, address, 0),
    PB_FIELD2(  2, UINT32  , REPEATED, STATIC  , OTHER, TxOutputType, address_n, address, 0),
    PB_FIELD2(  3, UINT64  , REQUIRED, STATIC  , OTHER, TxOutputType, amount, address_n, 0),
    PB_FIELD2(  4, ENUM    , REQUIRED, STATIC  , OTHER, TxOutputType, script_type, amount, 0),
    PB_FIELD2(  5, MESSAGE , OPTIONAL, STATIC  , OTHER, TxOutputType, multisig, script_type, &MultisigRedeemScriptType_fields),
    PB_FIELD2(  6, BYTES   , OPTIONAL, STATIC  , OTHER, TxOutputType, op_return_data, multisig, 0),
    PB_LAST_FIELD
};

const pb_field_t TxOutputBinType_fields[3] = {
    PB_FIELD2(  1, UINT64  , REQUIRED, STATIC  , FIRST, TxOutputBinType, amount, amount, 0),
    PB_FIELD2(  2, BYTES   , REQUIRED, STATIC  , OTHER, TxOutputBinType, script_pubkey, amount, 0),
    PB_LAST_FIELD
};

const pb_field_t TransactionType_fields[10] = {
    PB_FIELD2(  1, UINT32  , OPTIONAL, STATIC  , FIRST, TransactionType, version, version, 0),
    PB_FIELD2(  2, MESSAGE , REPEATED, STATIC  , OTHER, TransactionType, inputs, version, &TxInputType_fields),
    PB_FIELD2(  3, MESSAGE , REPEATED, STATIC  , OTHER, TransactionType, bin_outputs, inputs, &TxOutputBinType_fields),
    PB_FIELD2(  4, UINT32  , OPTIONAL, STATIC  , OTHER, TransactionType, lock_time, bin_outputs, 0),
    PB_FIELD2(  5, MESSAGE , REPEATED, STATIC  , OTHER, TransactionType, outputs, lock_time, &TxOutputType_fields),
    PB_FIELD2(  6, UINT32  , OPTIONAL, STATIC  , OTHER, TransactionType, inputs_cnt, outputs, 0),
    PB_FIELD2(  7, UINT32  , OPTIONAL, STATIC  , OTHER, TransactionType, outputs_cnt, inputs_cnt, 0),
    PB_FIELD2(  8, BYTES   , OPTIONAL, STATIC  , OTHER, TransactionType, extra_data, outputs_cnt, 0),
    PB_FIELD2(  9, UINT32  , OPTIONAL, STATIC  , OTHER, TransactionType, extra_data_len, extra_data, 0),
    PB_LAST_FIELD
};

const pb_field_t TxRequestDetailsType_fields[5] = {
    PB_FIELD2(  1, UINT32  , OPTIONAL, STATIC  , FIRST, TxRequestDetailsType, request_index, request_index, 0),
    PB_FIELD2(  2, BYTES   , OPTIONAL, STATIC  , OTHER, TxRequestDetailsType, tx_hash, request_index, 0),
    PB_FIELD2(  3, UINT32  , OPTIONAL, STATIC  , OTHER, TxRequestDetailsType, extra_data_len, tx_hash, 0),
    PB_FIELD2(  4, UINT32  , OPTIONAL, STATIC  , OTHER, TxRequestDetailsType, extra_data_offset, extra_data_len, 0),
    PB_LAST_FIELD
};

const pb_field_t TxRequestSerializedType_fields[4] = {
    PB_FIELD2(  1, UINT32  , OPTIONAL, STATIC  , FIRST, TxRequestSerializedType, signature_index, signature_index, 0),
    PB_FIELD2(  2, BYTES   , OPTIONAL, STATIC  , OTHER, TxRequestSerializedType, signature, signature_index, 0),
    PB_FIELD2(  3, BYTES   , OPTIONAL, STATIC  , OTHER, TxRequestSerializedType, serialized_tx, signature, 0),
    PB_LAST_FIELD
};

const pb_field_t IdentityType_fields[7] = {
    PB_FIELD2(  1, STRING  , OPTIONAL, STATIC  , FIRST, IdentityType, proto, proto, 0),
    PB_FIELD2(  2, STRING  , OPTIONAL, STATIC  , OTHER, IdentityType, user, proto, 0),
    PB_FIELD2(  3, STRING  , OPTIONAL, STATIC  , OTHER, IdentityType, host, user, 0),
    PB_FIELD2(  4, STRING  , OPTIONAL, STATIC  , OTHER, IdentityType, port, host, 0),
    PB_FIELD2(  5, STRING  , OPTIONAL, STATIC  , OTHER, IdentityType, path, port, 0),
    PB_FIELD2(  6, UINT32  , OPTIONAL, STATIC  , OTHER, IdentityType, index, path, &IdentityType_index_default),
    PB_LAST_FIELD
};

typedef struct {
    bool wire_in;
} wire_in_struct;

static const pb_field_t wire_in_field = 
      PB_FIELD2(50002, BOOL    , OPTEXT, STATIC  , FIRST, wire_in_struct, wire_in, wire_in, 0);

const pb_extension_type_t wire_in = {
    NULL,
    NULL,
    &wire_in_field
};

typedef struct {
    bool wire_out;
} wire_out_struct;

static const pb_field_t wire_out_field = 
      PB_FIELD2(50003, BOOL    , OPTEXT, STATIC  , FIRST, wire_out_struct, wire_out, wire_out, 0);

const pb_extension_type_t wire_out = {
    NULL,
    NULL,
    &wire_out_field
};

typedef struct {
    bool wire_debug_in;
} wire_debug_in_struct;

static const pb_field_t wire_debug_in_field = 
      PB_FIELD2(50004, BOOL    , OPTEXT, STATIC  , FIRST, wire_debug_in_struct, wire_debug_in, wire_debug_in, 0);

const pb_extension_type_t wire_debug_in = {
    NULL,
    NULL,
    &wire_debug_in_field
};

typedef struct {
    bool wire_debug_out;
} wire_debug_out_struct;

static const pb_field_t wire_debug_out_field = 
      PB_FIELD2(50005, BOOL    , OPTEXT, STATIC  , FIRST, wire_debug_out_struct, wire_debug_out, wire_debug_out, 0);

const pb_extension_type_t wire_debug_out = {
    NULL,
    NULL,
    &wire_debug_out_field
};


/* Check that field information fits in pb_field_t */
#if !defined(PB_FIELD_32BIT)
/* If you get an error here, it means that you need to define PB_FIELD_32BIT
 * compile-time option. You can do that in pb.h or on compiler command line.
 * 
 * The reason you need to do this is that some of your messages contain tag
 * numbers or field sizes that are larger than what can fit in 8 or 16 bit
 * field descriptors.
 */
STATIC_ASSERT((pb_membersize(HDNodePathType, node) < 65536 && pb_membersize(MultisigRedeemScriptType, pubkeys[0]) < 65536 && pb_membersize(TxInputType, multisig) < 65536 && pb_membersize(TxOutputType, multisig) < 65536 && pb_membersize(TransactionType, inputs[0]) < 65536 && pb_membersize(TransactionType, bin_outputs[0]) < 65536 && pb_membersize(TransactionType, outputs[0]) < 65536), YOU_MUST_DEFINE_PB_FIELD_32BIT_FOR_MESSAGES_HDNodeType_HDNodePathType_CoinType_MultisigRedeemScriptType_TxInputType_TxOutputType_TxOutputBinType_TransactionType_TxRequestDetailsType_TxRequestSerializedType_IdentityType)
#endif

#if !defined(PB_FIELD_16BIT) && !defined(PB_FIELD_32BIT)
#error Field descriptor for TxRequestSerializedType.serialized_tx is too large. Define PB_FIELD_16BIT to fix this.
#endif

