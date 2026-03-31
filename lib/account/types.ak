use aiken/collection/dict.{Dict}
use aiken/crypto.{Blake2b_224, Blake2b_256, Hash, Script, Signature, VerificationKey}
use cardano/transaction.{OutputReference}
use cardano/assets.{AssetName, PolicyId}

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

@list
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
