use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/crypto.{Blake2b_224, Blake2b_256, Hash, Script, Signature, VerificationKey}
use cardano/transaction.{Input, Output, OutputReference}
use cardano/assets.{AssetName, PolicyId, Value}
use aiken/cbor

////////////////////////////////////////////////////////////////////////////////
// Plutus helper types

pub type ScriptHash = Hash<Blake2b_224, Script>
pub type KeyHash = Hash<Blake2b_224, VerificationKey>
pub type DataHash = Hash<Blake2b_256, Data>
pub type DataMap = Dict<DataHash, Data>
pub type AssetList = Pairs<PolicyId, Pairs<AssetName, Int>>

////////////////////////////////////////////////////////////////////////////////
// High-level application types

pub type Id {
  policy_id: PolicyId,
  asset_name: AssetName
}

pub type IntentPayload {
  SendIntent {
    recipient: AssetName,
    assets: AssetList
  }
  ExchangeIntent {
    offer: AssetList,
    demand: AssetList
  }
}

pub type Intent {
  account: AssetName,
  nonce: Int,
  fee: Int,
  payload: IntentPayload,
  partial: Bool
}

pub type SignedIntent {
  intent: Intent,
  protected: ByteArray,
  external_aad: ByteArray,
  hashed: Bool,
  indefinite_bytestring: Bool,
  signature: Signature
}

pub type IntentRedeemer {
  NoncedIntent {
    intent: SignedIntent,
  }
  SpentIntent {
    input_index: Int,
  }
}

@list
pub type IntentSatisfaction {
  num: Int,
  denom: Int,
}

//@list
pub type SpendRedeemer {
  redeemer: IntentRedeemer,
  satisfaction: Option<IntentSatisfaction>
}

pub type AccountSpend {
  account: AssetName,
  intents: List<SpendRedeemer>,
}

pub type IdMintRedeemer {
  MintId{ out_ref: OutputReference }
  BurnId
}

////////////////////////////////////////////////////////////////////////////////
// Account data

pub type AccountDatum {
  Account {
    id: AssetName,
    verification_key: VerificationKey,
    pub_key_hash: KeyHash,
    nonce: Int,
  }
  Inbox {
    id: AssetName,
    pub_key_hash: KeyHash
  }
  UtxoIntent {
    account: AssetName,
    fee: Int,
    exchange: IntentPayload,
    partial: Bool
  }
}


pub type AccountRedeemer {
  SyncAccounts()
  SpendAccounts(List<AccountSpend>)
}

pub type OwnerAccumulator {
  input: Option<Input>,
  output: Option<Output>,
  gain: Value,
  loss: Value,
}

pub type AccountData {
  v_key: VerificationKey,
  pub_key_hash: KeyHash,
  nonce: Int,
}

pub type AccountOutput {
  policy_id: PolicyId,
  asset_name: AssetName,
  value: Value,
  data: AccountData,
}


test redeemer() {
  expect SpendAccounts(spends): AccountRedeemer = {
    expect Some(data) = cbor.deserialise(#"d87a9f9fd8799f5820008b998c245cae35896c8454a42f26ba52120583954eb8540d1a88e2c13954439f9fd8799fd8799fd8799f5820008b998c245cae35896c8454a42f26ba52120583954eb8540d1a88e2c1395443001a000f4240d8799f5820018b998c245cae35896c8454a42f26ba52120583954eb8540d1a88e2c1395443a140a1401a00989680ffd87980ff582aa201276761646472657373581d602cee9d3893cf424423c7236355976354e645807d44bd086b243b819b40d87980d879805840a3724e49005acf5d5850ecfcbc5373b3d64bc3cb94b3516a8e28c89e50130914c15f91d8a6305082f1d78d7ab94382aee87af7e01eb8a427b543792e4d790b0fffffd87a80ffffffffff")
    data
  }
  let spend = builtin.head_list(spends)
  let redeemer = builtin.head_list(spend.intents)
  expect None = redeemer.satisfaction
  trace(cbor.diagnostic(redeemer.satisfaction))
  trace(cbor.serialise(SpendRedeemer {
      redeemer: NoncedIntent {
        intent: SignedIntent {
          intent: Intent {
            account: "",
            nonce: 0,
            fee: 0,
            payload: SendIntent {
              recipient: "",
              assets: []
            },
            partial: False
          },
          protected: #"582aa201276761646472657373581d612042e66ff84b5b5cbfc64cc769682eb9ea55ec8a186c2fbe49c8dc72",
          external_aad: #"40",
          hashed: False,
          indefinite_bytestring: False,
          signature: #"4ea96350e1ff28f3b049673f1d0a0c9520a36f5d6e838f56de2f148bd328a9f6898958ca80c02d7c0c5d1e49b7eca2a5c21008983a2e0813fc8cc593aad5b80f"
        },
      },
      satisfaction: None
    }
  ))
  True
}

