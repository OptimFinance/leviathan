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

// ratio and continuing output index, or `None` for full
pub type IntentSatisfaction = Option<((Int, Int), Int)>

pub type IntentRedeemer {
  NoncedIntent {
    intent: SignedIntent,
  }
  SpentIntent {
    input_index: Int,
  }
}

pub type UtxoIntent {
  account: AssetName,
  fee: Int,
  exchange: IntentPayload,
  partial: Bool
}

pub type AccountSpend {
  account: AssetName,
  intents: List<(IntentRedeemer, IntentSatisfaction)>,
}

pub type IdMintRedeemer {
  MintId{ out_ref: OutputReference }
  BurnId
}

////////////////////////////////////////////////////////////////////////////////
// Account data

pub type AccountDatum {
  id: AssetName,
  verification_key: VerificationKey,
  pub_key_hash: KeyHash,
  nonce: Int,
}

pub type AccountRedeemer {
  SyncAccounts()
  SpendAccounts(List<AccountSpend>)
}

pub type InboxDatum {
  recipient: KeyHash
}
