/*
 * Copyright (c) Pavol Rusnak, SatoshiLabs
 *
 * Licensed under TREZOR License
 * see LICENSE file for details
 */

#include "flash.h"

/// class FlashOTP:
///     '''
///     '''
typedef struct _mp_obj_FlashOTP_t {
    mp_obj_base_t base;
} mp_obj_FlashOTP_t;

/// def __init__(self) -> None:
///     '''
///     '''
STATIC mp_obj_t mod_trezorio_FlashOTP_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_obj_FlashOTP_t *o = m_new_obj(mp_obj_FlashOTP_t);
    o->base.type = type;
    return MP_OBJ_FROM_PTR(o);
}

/// def FlashOTP.write(self, block: int, offset: int, data: bytes) -> None:
///     '''
///     Writes data to OTP flash
///     '''
STATIC mp_obj_t mod_trezorio_FlashOTP_write(size_t n_args, const mp_obj_t *args) {
    uint8_t block = mp_obj_get_int(args[1]);
    uint8_t offset = mp_obj_get_int(args[2]);
    mp_buffer_info_t data;
    mp_get_buffer_raise(args[3], &data, MP_BUFFER_READ);
    if (sectrue != flash_otp_write(block, offset, data.buf, data.len)) {
        mp_raise_ValueError("write failed");
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorio_FlashOTP_write_obj, 4, 4, mod_trezorio_FlashOTP_write);

/// def FlashOTP.read(self, block: int, offset: int, data: bytearray) -> None:
///     '''
///     Reads data from OTP flash
///     '''
STATIC mp_obj_t mod_trezorio_FlashOTP_read(size_t n_args, const mp_obj_t *args) {
    uint8_t block = mp_obj_get_int(args[1]);
    uint8_t offset = mp_obj_get_int(args[2]);
    mp_buffer_info_t data;
    mp_get_buffer_raise(args[3], &data, MP_BUFFER_WRITE);
    if (sectrue != flash_otp_read(block, offset, data.buf, data.len)) {
        mp_raise_ValueError("read failed");
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorio_FlashOTP_read_obj, 4, 4, mod_trezorio_FlashOTP_read);

/// def FlashOTP.lock(self, block: int) -> None:
///     '''
///     Lock OTP flash block
///     '''
STATIC mp_obj_t mod_trezorio_FlashOTP_lock(mp_obj_t self, mp_obj_t block) {
    uint8_t b = mp_obj_get_int(block);
    if (sectrue != flash_otp_lock(b)) {
        mp_raise_ValueError("lock failed");
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorio_FlashOTP_lock_obj, mod_trezorio_FlashOTP_lock);

/// def FlashOTP.is_locked(self, block: int) -> bool:
///     '''
///     Is OTP flash block locked?
///     '''
STATIC mp_obj_t mod_trezorio_FlashOTP_is_locked(mp_obj_t self, mp_obj_t block) {
    uint8_t b = mp_obj_get_int(block);
    return flash_otp_is_locked(b) ? mp_const_true : mp_const_false;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorio_FlashOTP_is_locked_obj, mod_trezorio_FlashOTP_is_locked);

STATIC const mp_rom_map_elem_t mod_trezorio_FlashOTP_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_read), MP_ROM_PTR(&mod_trezorio_FlashOTP_read_obj) },
    { MP_ROM_QSTR(MP_QSTR_write), MP_ROM_PTR(&mod_trezorio_FlashOTP_write_obj) },
    { MP_ROM_QSTR(MP_QSTR_lock), MP_ROM_PTR(&mod_trezorio_FlashOTP_lock_obj) },
    { MP_ROM_QSTR(MP_QSTR_is_locked), MP_ROM_PTR(&mod_trezorio_FlashOTP_is_locked_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorio_FlashOTP_locals_dict, mod_trezorio_FlashOTP_locals_dict_table);

STATIC const mp_obj_type_t mod_trezorio_FlashOTP_type = {
    { &mp_type_type },
    .name = MP_QSTR_FlashOTP,
    .make_new = mod_trezorio_FlashOTP_make_new,
    .locals_dict = (void*)&mod_trezorio_FlashOTP_locals_dict,
};