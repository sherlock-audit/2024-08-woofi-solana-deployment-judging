# Issue H-1: `rebate_info` and `rebate_manager` are unable to sign the CPI call due to an incorrect implementation of the `seeds` function 

Source: https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/29 

## Found by 
g, shaflow01
### Summary

`rebate_info` and `rebate_manager` will not be able to sign the CPI message because their `seeds` function has been implemented incorrectly.

### Root Cause

The implementation of the seeds function is incorrect because the correct seed needs to include the full seed phrase and the bump, but the seeds function does not include the bump.

https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/1c4c9c622e8c44ae2f8cd4219c7c2a0181f25ca0/WOOFi_Solana/programs/rebate_manager/src/state/rebate_manager.rs#L54
```rust
    pub fn seeds(&self) -> [&[u8]; 2] {
        [
            REBATEMANAGER_SEED.as_bytes(),
            self.quote_token_mint.as_ref(),
        ]
    }
```
https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/1c4c9c622e8c44ae2f8cd4219c7c2a0181f25ca0/WOOFi_Solana/programs/rebate_manager/src/state/rebate_info.rs#L51
```rust
    pub fn seeds(&self) -> [&[u8]; 3] {
        [
            REBATEINFO_SEED.as_bytes(),
            self.rebate_manager.as_ref(),
            self.rebate_authority.as_ref(),
        ]
    }
```

### Internal pre-conditions

None

### External pre-conditions

None

### Attack Path

None

### Impact

It will prevent the `claim_rebate_fee` and `withdraw` operations from executing, resulting in tokens being permanently locked in the contract.

### PoC

_No response_

### Mitigation

Here is an example of fixing rebate_manager:
```diff
#[account]
#[derive(InitSpace)]
pub struct RebateManager {
    pub authority: Pubkey, // 32

    #[max_len(ADMIN_AUTH_MAX_LEN)]
    pub admin_authority: Vec<Pubkey>,

    pub quote_token_mint: Pubkey, // 32

    pub token_vault: Pubkey, // 32

+   pub rebate_manager_bump: [u8; 1],
}
```
```diff
    pub fn seeds(&self) -> [&[u8]; 2] {
        [
            REBATEMANAGER_SEED.as_bytes(),
            self.quote_token_mint.as_ref(),
+           self.rebate_manager_bump.as_ref(),
        ]
    }
```
```diff
    pub fn initialize(
        &mut self,
        authority: Pubkey,
        quote_token_mint: Pubkey,
        token_vault: Pubkey,
+       bump: u8.
    ) -> Result<()> {
        self.authority = authority;
        self.quote_token_mint = quote_token_mint;
        self.token_vault = token_vault;
+       self.rebate_manager_bump = [bump];
        Ok(())
    }

```
```diff
pub fn handler(ctx: Context<CreateRebateManager>) -> Result<()> {
    let authority = ctx.accounts.authority.key();
    let quote_token_mint = ctx.accounts.quote_token_mint.key();
    let token_vault = ctx.accounts.token_vault.key();
+   let bump = ctx.bumps.rebate_manager;
    let rebate_manager = &mut ctx.accounts.rebate_manager;

-   rebate_manager.initialize(authority, quote_token_mint, token_vault);
+   rebate_manager.initialize(authority, quote_token_mint, token_vault, bump);
}
```
The fix for `rebate_info` is the same as described above.



## Discussion

**toprince**

Valid.
same with https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/18

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/woonetwork/WOOFi_Solana/pull/32


# Issue H-2: Quote pools are expected to have same base token and quote token but this is not enforced in swaps 

Source: https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/64 

## Found by 
S3v3ru5, g
### Summary

The missing [constraint](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L79-L84) that enforces quote pools should have the same base and quote token will cause swap fees to be deducted from non-quote pools.

By design, [quote pools](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/util/token.rs#L11-L15) are pools with the same base and quote token. The development team has confirmed this. All [swap fees](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L192-L194) should come from quote pools.  

```rust
  // record fee into account
  woopool_quote.sub_reserve(swap_fee).unwrap();
  woopool_quote.add_unclaimed_fee(swap_fee).unwrap();
```

### Root Cause

In [`swap.rs:79-84`](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L79-L84), there is no constraint that enforces that the pool used as the quote pool has the same base token and quote token. 

```rust
  #[account(mut,
      has_one = wooconfig,
      constraint = woopool_quote.token_mint == woopool_from.quote_token_mint,
      constraint = woopool_quote.authority == woopool_from.authority,
  )]
  woopool_quote: Box<Account<'info, WooPool>>,
```

This means that non-quote pools can be used as quote pools during [swaps](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L192-L194) and swap fees will be deducted from these. 
```rust
  // record fee into account
  woopool_quote.sub_reserve(swap_fee).unwrap();
  woopool_quote.add_unclaimed_fee(swap_fee).unwrap();
```

### Internal pre-conditions

None

### External pre-conditions

None

### Attack Path

1. Anyone can execute swaps by invoking the [`swap`](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/lib.rs#L183-L185) instruction and passing a non-quote pool as a `woopool_quote`. The [constraints](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L79-L84) will allow it as long as the `woopool_quote`'s base token is the same as the `woopool_from`'s quote token and the pools have the same owners. 

### Impact

Swap fees can be deducted from non-quote pools instead of quote pools only.

### PoC

_No response_

### Mitigation

Consider adding a [constraint](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L79-L84) that enforces that the quote pool is a pool with the same base and quote token.



## Discussion

**toprince**

Need investigation here.
Same with https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/40

# Issue M-1: An admin authority initializing RebateInfo will make claim_rebate_fee unusable 

Source: https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/13 

## Found by 
Albort, D1r3Wolf, g, zigtur
### Summary

A `ClaimRebateFee` constraint enforces that `rebate_info.authority == rebate_manager.authority`. This will always be false when an admin authority initialized the `rebate_info`, leading the `rebate_info.rebate_authority` to not be able to claim their rebate fee.

### Root Cause

In [`claim_rebate_fee.rs:26`](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/claim_rebate_fee.rs#L26), there is an incorrect constraint.

### Internal pre-conditions

1. An admin authority needs to initialize the `rebate_info` through the `create_rebate_info` instruction. It is made possible through the constraint at [`create_rebate_info.rs#L17`](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/admin/create_rebate_info.rs#L17).

### External pre-conditions

None.

### Attack Path

_No response_

### Impact

- The rebate authority suffers from 100% rebate fee loss as it is not able to claim (through the `claim_rebate_fee` instruction).

### PoC

_No response_

### Mitigation

This constraint should be deleted. Fixing it to check if the `rebate_info.authority` is an admin authority will lead to the same issue being triggered when admin authorities are updated.



## Discussion

**toprince**

Need further investigation.

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/woonetwork/WOOFi_Solana/pull/28


# Issue M-2: Attacker can control rebate managers for supported tokens since there is only 1 rebate manager per quote token 

Source: https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/16 

## Found by 
LZ\_security, g, shaflow01, zigtur
### Summary

The rebate manager uses the following [seeds](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/admin/create_rebate_manager.rs#L18-L21) on creation:
- `REBATE_MANAGER_SEED`
- `quote_token_mint`

This means that only 1 rebate manager can be created per quote token. Any attacker can block rebate functionality by front-running the creation of rebate managers for all the supported tokens (e.g. USDC, USDT, SOL).

### Root Cause

In [`create_rebate_manager.rs:18-21`](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/admin/create_rebate_manager.rs#L18-L21), the choice to allow only 1 rebate manager per quote token is a mistake. Attackers can front-run the creation of rebate managers for supported quote tokens so they control all rebate managers.

### Internal pre-conditions

None

### External pre-conditions

None

### Attack Path

1. Attacker front-runs any [`create_rebate_manager()`](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/admin/create_rebate_manager.rs#L38-L46) calls with their own.

### Impact

Rebate functionality will be blocked for the quote tokens the attacker controls.

### PoC

_No response_

### Mitigation

Consider using the [`authority` ](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/admin/create_rebate_manager.rs#L12) as part of the [seeds](https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/rebate_manager/src/instructions/admin/create_rebate_manager.rs#L18-L21) when creating a rebate manager.



## Discussion

**toprince**

Need investigate this further.

**toprince**

Any one can deploy a contract and gain owner authority.
Like anyone can deploy a new coin called itself USDT...
You can already create a rebate manager now. But we will not use that.
So not see pre create is a issue...

**zigtur**

@toprince Let's say that the project supports USDC and SOL for a week. Then after a week, project wants to support USDT.
Here the attack would be exploitable.

Let's say project supports those 3 tokens at deployment. But then, in one month project may want to support another token. Here the attack would be exploitable.
This design is highly "non-future proof" and the contest details lets think that project plan to support more in the future:
> We manually add the supported token pairs into the swap. **The initial list is: SOL, USDT, USDC**. Any two of them can form a swap pair.

# Issue M-3: Missing permission control in create_oracle and create_pool. 

Source: https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/54 

## Found by 
0xeix, LZ\_security, Q7, S3v3ru5, calc1f4r, dod4ufn, g, shaflow01, zigtur
## Summary
Missing permission control in create_oracle and create_pool.
## Vulnerability Detail
```rust
#[derive(Accounts)]
pub struct CreateWooracle<'info> {
    pub wooconfig: Box<Account<'info, WooConfig>>,
    pub token_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = admin,
        space = 8 + Wooracle::INIT_SPACE,
        seeds = [
            WOORACLE_SEED.as_bytes(),
            wooconfig.key().as_ref(),
            token_mint.key().as_ref(),
            feed_account.key().as_ref(),
            price_update.key().as_ref()
            ],
        bump,
    )]
    wooracle: Account<'info, Wooracle>,
    #[account(mut)]
@>>    admin: Signer<'info>,
    system_program: Program<'info, System>,
    /// CHECK: This is the Pyth feed account
    feed_account: AccountInfo<'info>,
    // Add this account to any instruction Context that needs price data.
    // Warning:
    // users must ensure that the account passed to their instruction is owned by the Pyth pull oracle program.
    // Using Anchor with the Account<'info, PriceUpdateV2> type will automatically perform this check.
    // However, if you are not using Anchor, it is your responsibility to perform this check.
    price_update: Account<'info, PriceUpdateV2>,

    quote_token_mint: Account<'info, Mint>,
    /// CHECK: This is the Quote token's pyth feed account
    quote_feed_account: AccountInfo<'info>,
    // Add this account to any instruction Context that needs price data.
    // Warning:
    // users must ensure that the account passed to their instruction is owned by the Pyth pull oracle program.
    // Using Anchor with the Account<'info, PriceUpdateV2> type will automatically perform this check.
    // However, if you are not using Anchor, it is your responsibility to perform this check.
    quote_price_update: Account<'info, PriceUpdateV2>,
}

pub fn handler(ctx: Context<CreateWooracle>, maximum_age: u64) -> Result<()> {
    ctx.accounts.wooracle.wooconfig = ctx.accounts.wooconfig.key();
@>>    ctx.accounts.wooracle.authority = ctx.accounts.admin.key();
    ctx.accounts.wooracle.token_mint = ctx.accounts.token_mint.key();
    ctx.accounts.wooracle.feed_account = ctx.accounts.feed_account.key();
    ctx.accounts.wooracle.price_update = ctx.accounts.price_update.key();

   //----skip
}
```
From the code, it is evident that create_wooracle lacks permission control, allowing anyone to create an oracle.
```rust
#[derive(Accounts)]
pub struct CreatePool<'info> {
    pub wooconfig: Box<Account<'info, WooConfig>>,
    pub token_mint: Account<'info, Mint>,
    pub quote_token_mint: Account<'info, Mint>,

    #[account(mut)]
@>>    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + WooPool::INIT_SPACE,
        seeds = [
          WOOPOOL_SEED.as_bytes(),
          wooconfig.key().as_ref(),
          token_mint.key().as_ref(),
          quote_token_mint.key().as_ref()
        ],
        bump)]
    pub woopool: Box<Account<'info, WooPool>>,

    #[account(
        init,
        payer = authority,
        token::mint = token_mint,
        token::authority = woopool
      )]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        has_one = wooconfig,
@>>        has_one = authority,
        has_one = token_mint,
        has_one = quote_token_mint
    )]
    wooracle: Account<'info, Wooracle>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

```
From the above code, it is clear that the permission control for create_pool requires its authority to match wooracle.authority. However, since anyone can create an oracle, an attacker could create an oracle and then create a pool based on that oracle. This breaks the statement made in the README.
"Functions need admin authority: claim_fee claim_rebate_fee create_oracle create_pool create_rebate_pool deposit set_pool_admin set_pool_state (all handlers in this file) set_woo_admin set_woo_state(all handlers in this file)"

## Impact
There are two further impacts:

	1.When the protocol has been running for a period of time, such as 6 months, and wants to add other token pairs into the swap (e.g., WETH-USDT), the real administrator may not be able to create the WETH oracle because the WETH oracle was created by someone else.

    2. An attacker could create oracles and pools for other token pairs (e.g., WETH-USDT) and set the oracle’s price and bounds to manipulate prices. Even if there’s a comparison with Pyth’s prices, it could still pass. As a result, the attacker could trade with the manipulated prices against pools (e.g., USDT, USDC) and steal funds from the pools.
## Code Snippet
https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/admin/create_wooracle.rs#L42

https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/admin/create_pool.rs#L8
## Tool used

Manual Review

## Recommendation
Set the admin parameter in CreateWooracle to admin = wooconfig.authority.




## Discussion

**toprince**

Impact 1 is valid, it is low impact.
Impact 2 is not valid, please verify if it can swap with correct pool.

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/woonetwork/WOOFi_Solana/pull/31


# Issue M-4: State changes are overwritten during anchor serialization when two accounts are the same 

Source: https://github.com/sherlock-audit/2024-08-woofi-solana-deployment-judging/issues/73 

## Found by 
S3v3ru5
### Summary

The swap operation takes in 3 pool accounts:

1. woopool_from
2. woopool_to
3. woopool_quote

Case 1:
In Base-to-Quote Swap, woopool_from is base token pool. woopool_to, woopool_quote will be the quote token pool and both are same accounts `woopool_to == woopool_quote`.

Case 2:
In Quote-to-Base Swap, woopool_to is base token pool. woopool_from, woopool_quote will be the quote token pool and both are same accounts `woopool_from == woopool_quote`.

Case 3:
In the case of Base-to-Base all three pools will be different.

In case 1 and case 2, two of the passed-in accounts are same. Because of how anchor works, at the end of the execution, changes of only one pool will be saved. For example in case 1 when `woopool_to`, `woopool_quote` are same, at the end of the program execution, updates to either `woopool_to` or `woopool_quote` are recorded.

Anchor `#[derive(Accounts)]` macro works by creating a in-memory copy of the account data, modifying the memory and then writing back into the account data:

- For each of the account, Anchor performs required checks based on the type `Account<'info, WooConfig>`, `Program<'info, Token>`, etc.
- For `Account<'a, T>` type accounts, Anchor deserializes the `AccountInfo.data` into `T`. For e.g, if account X is passed for `Account<'a, WooPool>` then Anchor deserializes `X.data` into type `WooPool` and keeps the copy in memory.
     -  Same as `memory` copies of state variables in Solidity.
 - The deserialized in-memory copies of the accounts are passed to the instruction-handler: for example `swap` function is an instruction handler.
 - After the instruction handler finishes execution, Anchor serializes the accounts and writes into the account data.
 - The account data is persistent and hence the state changes are saved.


Consider a Solidity function which copies a `struct` state variable into memory, changes the values in memory and at the end of the function copies the memory values into the state variable. Anchor does the same thing.

This leads to a `storage overwrite` issue when two of the passed-in accounts are same. When the second struct written into account `data`, it will overwrite any changes that are present in the first struct.

The `swap` instruction handler performs the following updates to the pools:

1. Add `from_amount` to `woopool_from` reserve
2. Subtract  `to_amount` from `woopool_to` reserve
3. Subtract `swap_fee` from `woopool_quote` reserve
4. Add `swap_fee` to unclaimed fee

https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L189-L194

`woopool_quote` is serialized last hence it will overwrite any previous changes if they are same accounts.

- If `woopool_from` == `woopool_quote`:
    - Update in `1` will be overwritten by `3` and `4`.
    - `from_amount` will not be added to `woopool_from` (quote pool) reserves
- if `woopool_to` == `woopool_quote`:
    - Update in `2` will be overwritten by `3` and `4`. 
    - `to_amount` will not be deducted from the `woopool_to` (quote pool) reserves

### Root Cause

The `swap` function tries to handle all type of swaps in a single instruction allowing for cases where two writable accounts are the same leading to `storage overwrite` issues

https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L13-L84

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

User performs a swap: either Base to quote or quote to base. The reserves of the quote will not be updated correctly.

### Impact

- If swap sells quote:
    - `from_amount` will not be added to `woopool_from` (quote pool) reserves
- if swap sells base for quote:
    - `to_amount` will not be deducted from the `woopool_to` (quote pool) reserves
 
This leads to incorrect accounting of `quote pool` reserves variable. 

1. The reserve will be higher than the quote pool token vault balance Or
2. The reserve will be lower than the quote pool token vault balance

Additional to incorrect state, because balance is checked before transfering tokens in claim_fee, the issue might prevent admin from claiming fees. The issue might have additional implications that aren't noted here.

### PoC

In the `1_woofi_swap.ts` test file, update the `swap_from_sol_to_usdc` test to print the reserve values of the `toPool` before and after the swap.

Add the following at line 265 in `tests/1_woofi_swap.ts`:
```js

      let toPoolDataBefore = null;
      try {
        toPoolDataBefore = await program.account.wooPool.fetch(toPoolParams.woopool);
      } catch (e) {
          console.log(e);
          console.log("fetch failed");
          return;
      }
      console.log("toPool reserve before swap:" + toPoolDataBefore.reserve);
      console.log("toPool unclaimed fee before swap:" + toPoolDataBefore.unclaimedFee);
```

and Add the following at line 357 at the end of the that test (after `swap` is called`:
```js
        let toPoolDataAfter = null;
        try {
          toPoolDataAfter = await program.account.wooPool.fetch(toPoolParams.woopool);
        } catch (e) {
            console.log(e);
            console.log("fetch failed");
            return;
        }
        console.log("toPool reserve after swap:" + toPoolDataAfter.reserve);
        console.log("toPool unclaimed fee after swap:" + toPoolDataAfter.unclaimedFee);
```
The output will be:
```text
    #swap_between_sol_and_usdc
fromWallet PublicKey:Cybv9pDy9MoysaTk3gkRi3RCtW5gz1jRzZouF47TyfnB
solWalletTokenAccount:GCGi8N26WRcwBedHCFoRo8iycWwLadaNYJx1CW7PyJQ
usdcWalletTokenAccount:Aynux9Ei1FczuPNb5i4Z6cgJisABx3Ty5xNZUfsR6Gst
fromWallet Balance:0
fromTokenAccount amount:1000000
fromTokenAccount decimals:9
toPool reserve before swap:200000
toPool unclaimed fee before swap:0
price - 14597424250
feasible - 1
price - 0
feasible - 0
toAmount:136775
swapFee:4231
toTokenAccount amount:136775
toTokenAccount decimals:6
toPool reserve after swap:195769
toPool unclaimed fee after swap:4231
      ✔ swap_from_sol_to_usdc (3274ms)
```

In the test, `woopool_to` == `woopool_quote` == `USDC pool`. The `reserve` of the USDC pool should be

```solidity
usdcPool.reserve = usdcPool.reserve - toAmount - swapFee = 200000 - 136775 - 4231
```

However, in the output it can be seen that, the `usdcPool.reserve` is equal to `reserve - swap_fee = 200000 - 4231 = 195769`

The deduction of `to_amount` from the `woopool_to.reserve` is not present:

https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L190

Only the `swap_fee` deduction is preserved because it was deducted from `woopool_quote`:

https://github.com/sherlock-audit/2024-08-woofi-solana-deployment/blob/main/WOOFi_Solana/programs/woofi/src/instructions/swap.rs#L193

When Anchor serialized the accounts at the end, the `woopool_to` is first written to the account data and then the `woopool_quote`. Because both are same accounts, the changes in `woopool_to` are overwritten when `woopool_quote` is serialized and written to account data.

In case of swap usdc to sol, the changes in `woopool_from` will be overwritten by the `woopool_quote`.

### Mitigation

Divide the `swap` functions into individual `sell_base`, `sell_quote`, and `sell_base_to_base` functions.



## Discussion

**toprince**

Oh....anchor...

**S3v3ru5**

The judging comments include "No loss of funds" as a reason for the medium severity. The `incase_token_got_stuck` can be used to retrieve any tokens from the vaults.

I do not think only loss of funds issues can be consider as High.

The `reserves` variable is a core state variable and it will be wrong because of the above issue. There are multiple implications of the incorrect `reserves` variable

- The issue #68 lists one such impact of this issue.
- The vault token-balance could be greater than reserves when Quote to Base swap is performed. The valid swaps will be rejected even when vault has enough tokens for the swap.
- Pool admin cannot use the `withdraw` function to withdraw the `token balance - reserves` tokens if token-balance is greater than the reserve.

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/woonetwork/WOOFi_Solana/pull/33


