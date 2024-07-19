library;

use std::{b512::B512, primitive_conversions::u256::*, u128::U128};

#[test]
fn u256_from_u8() {
    let u256_1 = u256::from(u8::min());
    let u256_2 = u256::from(2_u8);
    let u256_3 = u256::from(u8::max());

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x00000000000000000000000000000000000000000000000000000000000000ff_u256,
    );
}

#[test]
fn u256_into_u8() {
    let u8_1 = u8::min();
    let u8_2 = 2_u8;
    let u8_3 = u8::max();

    let u256_1: u256 = u8_1.into();
    let u256_2: u256 = u8_2.into();
    let u256_3: u256 = u8_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x00000000000000000000000000000000000000000000000000000000000000ff_u256,
    );
}

#[test]
fn u256_from_u16() {
    let u256_1 = u256::from(u16::min());
    let u256_2 = u256::from(2_u16);
    let u256_3 = u256::from(u16::max());

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x000000000000000000000000000000000000000000000000000000000000ffff_u256,
    );
}

#[test]
fn u256_into_u16() {
    let u16_1 = u16::min();
    let u16_2 = 2u16;
    let u16_3 = u16::max();

    let u256_1: u256 = u16_1.into();
    let u256_2: u256 = u16_2.into();
    let u256_3: u256 = u16_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x000000000000000000000000000000000000000000000000000000000000ffff_u256,
    );
}

#[test]
fn u256_from_u32() {
    let u256_1 = u256::from(u32::min());
    let u256_2 = u256::from(2u32);
    let u256_3 = u256::from(u32::max());

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x00000000000000000000000000000000000000000000000000000000ffffffff_u256,
    );
}

#[test]
fn u256_into_u32() {
    let u32_1 = u32::min();
    let u32_2 = 2u32;
    let u32_3 = u32::max();

    let u256_1: u256 = u32_1.into();
    let u256_2: u256 = u32_2.into();
    let u256_3: u256 = u32_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x00000000000000000000000000000000000000000000000000000000ffffffff_u256,
    );
}

#[test]
fn u256_from_u64() {
    let u256_1 = u256::from(u64::min());
    let u256_2 = u256::from(2u64);
    let u256_3 = u256::from(u64::max());

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x000000000000000000000000000000000000000000000000ffffffffffffffff_u256,
    );
}

#[test]
fn u256_into_u64() {
    let u64_1 = u64::min();
    let u64_2 = 2u64;
    let u64_3 = u64::max();

    let u256_1: u256 = u64_1.into();
    let u256_2: u256 = u64_2.into();
    let u256_3: u256 = u64_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x000000000000000000000000000000000000000000000000ffffffffffffffff_u256,
    );
}

#[test]
fn u256_from_b256() {
    let u256_1 = u256::from(0x0000000000000000000000000000000000000000000000000000000000000000);
    let u256_2 = u256::from(0x0000000000000000000000000000000000000000000000000000000000000002);
    let u256_3 = u256::from(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256,
    );
}

#[test]
fn u256_into_b256() {
    let b256_1 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let b256_2 = 0x0000000000000000000000000000000000000000000000000000000000000002;
    let b256_3 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    let u256_1: u256 = b256_1.into();
    let u256_2: u256 = b256_2.into();
    let u256_3: u256 = b256_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256,
    );
}

#[test]
fn u256_from_u128() {
    let u256_1 = u256::from(U128::from((u64::min(), u64::min())));
    let u256_2 = u256::from(U128::from((0u64, 2u64)));
    let u256_3 = u256::from(U128::from((u64::max(), u64::max())));

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff_u256,
    );
}

#[test]
fn u256_into_u128() {
    let u128_1 = U128::from((u64::min(), u64::min()));
    let u128_2 = U128::from((0u64, 2u64));
    let u128_3 = U128::from((u64::max(), u64::max()));

    let u256_1: u256 = u128_1.into();
    let u256_2: u256 = u128_2.into();
    let u256_3: u256 = u128_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );
    assert(
        u256_3 == 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff_u256,
    );
}

#[test]
fn u256_from_tuple() {
    let u256_1 = u256::from((u64::min(), u64::min(), u64::min(), u64::min()));
    let u256_2 = u256::from((1, 2, 3, 4));
    let u256_3 = u256::from((u64::max(), u64::max(), u64::max(), u64::max()));

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000001000000000000000200000000000000030000000000000004_u256,
    );
    assert(
        u256_3 == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256,
    );
}

#[test]
fn u256_into_tuple() {
    let tuple_1 = (u64::min(), u64::min(), u64::min(), u64::min());
    let tuple_2 = (1, 2, 3, 4);
    let tuple_3 = (u64::max(), u64::max(), u64::max(), u64::max());

    let u256_1: u256 = tuple_1.into();
    let u256_2: u256 = tuple_2.into();
    let u256_3: u256 = tuple_3.into();

    assert(
        u256_1 == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );
    assert(
        u256_2 == 0x0000000000000001000000000000000200000000000000030000000000000004_u256,
    );
    assert(
        u256_3 == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256,
    );
}

#[test]
fn u256_try_from_b512() {
    let b512_1 = B512::new();
    let b512_2 = B512::from((
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000002,
    ));
    let b512_3 = B512::from((
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    ));
    let b512_4 = B512::from((
        0x0000000000000000000000000000000000000000000000000000000000000001,
        0x0000000000000000000000000000000000000000000000000000000000000000,
    ));

    let u256_1 = u256::try_from(b512_1);
    let u256_2 = u256::try_from(b512_2);
    let u256_3 = u256::try_from(b512_3);
    let u256_4 = u256::try_from(b512_4);

    assert(u256_1.is_some());
    assert(
        u256_1
            .unwrap() == 0x0000000000000000000000000000000000000000000000000000000000000000_u256,
    );

    assert(u256_2.is_some());
    assert(
        u256_2
            .unwrap() == 0x0000000000000000000000000000000000000000000000000000000000000002_u256,
    );

    assert(u256_3.is_some());
    assert(
        u256_3
            .unwrap() == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256,
    );

    assert(u256_4.is_none());
}
