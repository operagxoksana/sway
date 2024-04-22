script;

use core::codec::*;
use context_testing_abi::*;

#[cfg(experimental_new_encoding = false)]
const CONTRACT_ID = 0xe83ed45906627117f00f60e47140c6100b4b69133389a2dafd35bc3282329385;
#[cfg(experimental_new_encoding = true)]
const CONTRACT_ID = 0x1901a76a101ec5de439100f2f21896be0893fe8a783be41206dd8c61cb81b52f;

fn main() -> bool {
    let gas: u64 = u64::max();
    let amount: u64 = 11;
    let other_contract_id = ContractId::from(CONTRACT_ID);
    let other_contract_id_b256: b256 = other_contract_id.into();
    let base_asset_id = AssetId::base();

    let test_contract = abi(ContextTesting, other_contract_id_b256);

    // test Context::contract_id():
    let returned_contract_id = test_contract.get_id {
        gas: gas,
        coins: 0,
        asset_id: AssetId::base().bits(),
    }();
    let returned_contract_id_b256: b256 = returned_contract_id.into();
    assert(returned_contract_id_b256 == other_contract_id_b256);

    // @todo set up a test contract to mint some assets for testing balances.
    // test Context::this_balance():
    let returned_this_balance = test_contract.get_this_balance {
        gas: gas,
        coins: 0,
        asset_id: AssetId::base().bits(),
    }(base_asset_id);
    assert(returned_this_balance == 0);

    // test Context::balance_of_contract():
    let returned_contract_balance = test_contract.get_balance_of_contract {
        gas: gas,
        coins: 0,
        asset_id: AssetId::base().bits(),
    }(base_asset_id, other_contract_id);
    assert(returned_contract_balance == 0);

    // TODO: The checks below don't work (AssertIdNotFound). The test should be
    // updated to forward coins that are actually available.
    // test Context::msg_value():
    /*let returned_amount = test_contract.get_amount {
        gas: gas, coins: amount, asset_id: AssetId::base()
    }
    ();
    assert(returned_amount == amount);

    // test Context::msg_asset_id():
    let returned_asset_id = test_contract.get_asset_id {
        gas: gas, coins: amount, asset_id: AssetId::base()
    }
    ();
    assert(returned_asset_id.into() == AssetId::base());

    // test Context::msg_gas():
    // @todo expect the correct gas here... this should fail using `1000`
    let gas = test_contract.get_gas {
        gas: gas, coins: 0, asset_id: AssetId::base()
    }
    ();
    assert(gas == 1000);

    // test Context::global_gas():
    // @todo expect the correct gas here... this should fail using `1000`
    let global_gas = test_contract.get_global_gas {
        gas: gas, coins: 0, asset_id: AssetId::base()
    }
    ();
    assert(global_gas == 1000);*/
    true
}
