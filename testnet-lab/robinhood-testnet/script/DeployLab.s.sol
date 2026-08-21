// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// UNVERIFIED / UNCOMPILED: authored without a local `forge` toolchain or
// network access to fetch `lib/seadrop` available. Before running this:
//   1. `forge install ProjectOpenSea/seadrop` in this directory.
//   2. Open the installed `lib/seadrop/src/SeaDrop.sol` and
//      `lib/seadrop/src/ERC721SeaDrop.sol` and confirm the exact function
//      names/signatures below (`updatePublicDrop`, `updateAllowList`,
//      `setMaxSupply`, `updateAllowedSeaDrop`, the `PublicDrop`/
//      `AllowListData`/`MintParams` struct shapes) still match what is
//      written here -- do not trust this comment or this script blindly.
//   3. `forge build` and read every compiler warning.
//   4. `forge script script/DeployLab.s.sol --rpc-url $RH_TESTNET_RPC
//      --broadcast -vvvv` only after all of the above, and only against
//      chain id 46630 (enforced below, but verify it yourself too).

import {Script, console2} from "forge-std/Script.sol";
import {SeaDrop} from "seadrop/SeaDrop.sol";
import {PublicDrop, AllowListData} from "seadrop/lib/SeaDropStructs.sol";
import {RobinhoodTestnetCollection} from "../src/RobinhoodTestnetCollection.sol";

/// Deploys (or reuses) a SeaDrop instance and a tiny disposable
/// RobinhoodTestnetCollection, then configures:
///   - a public free-mint stage, wallet limit 2, max supply 20, a start
///     time read from `PUBLIC_STAGE_START` (defaults to "1 hour from now"
///     so it is schedulable in the future for a timed T=0 test)
///   - a single-leaf allow-list stage for exactly one test wallet, read
///     from `ALLOWLIST_TEST_WALLET`
///
/// Hard-guarded to Robinhood Chain Testnet (46630) ONLY. Reverts
/// immediately on any other connected chain id -- there is no fallback.
contract DeployLab is Script {
    uint256 constant ROBINHOOD_TESTNET_CHAIN_ID = 46630;
    uint16 constant MAX_SUPPLY = 20;
    uint16 constant PUBLIC_WALLET_LIMIT = 2;

    function run() external {
        require(
            block.chainid == ROBINHOOD_TESTNET_CHAIN_ID,
            "ABORT: connected chain is not Robinhood Chain Testnet (46630). Refusing to deploy. Never falls back to 4663 (mainnet) or any other chain."
        );

        // Never a literal key in this file, in an example, or in git --
        // read only from the environment at run time.
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address allowlistTestWallet = vm.envAddress("ALLOWLIST_TEST_WALLET");
        uint256 publicStageStart = vm.envOr("PUBLIC_STAGE_START", block.timestamp + 1 hours);

        vm.startBroadcast(deployerKey);

        SeaDrop seaDrop = new SeaDrop();
        console2.log("SeaDrop deployed:", address(seaDrop));

        address[] memory allowedSeaDrop = new address[](1);
        allowedSeaDrop[0] = address(seaDrop);

        RobinhoodTestnetCollection nft = new RobinhoodTestnetCollection(
            "Kairox Robinhood Testnet Lab",
            "KRTLAB",
            allowedSeaDrop
        );
        console2.log("Test collection deployed:", address(nft));

        nft.setMaxSupply(MAX_SUPPLY);

        // Public stage: free, wallet limit 2, open now (start time can be
        // overridden via PUBLIC_STAGE_START for a genuine timed-T=0 test).
        PublicDrop memory publicDrop = PublicDrop({
            mintPrice: 0,
            startTime: uint48(publicStageStart),
            endTime: uint48(publicStageStart + 7 days),
            maxTotalMintableByWallet: PUBLIC_WALLET_LIMIT,
            feeBps: 0,
            restrictFeeRecipients: false
        });
        nft.updatePublicDrop(address(seaDrop), publicDrop);
        console2.log("Public stage configured, starts at:", publicStageStart);

        // Allow-list stage: a single-leaf tree for exactly one test
        // wallet -- deliberately the simplest possible genuine Merkle
        // proof (leaf == root, empty proof), matching the pattern Kairox's
        // own real-localhost E2E tests already exercise.
        // NOTE: computing the real Merkle root/leaf requires the exact
        // MintParams this stage will use -- do this off-chain (e.g. with a
        // small script using the same `protocol::seadrop_crypto` leaf
        // encoding Kairox uses) and pass the resulting root here. Left as
        // an explicit TODO rather than guessed, since a wrong root would
        // make the allow-list stage silently unusable rather than unsafe.
        console2.log(
            "Allow-list stage NOT auto-configured -- compute the single-leaf root for wallet",
            allowlistTestWallet,
            "and call nft.updateAllowList(...) separately (see README)."
        );

        vm.stopBroadcast();

        console2.log("=== Deployed addresses (copy into your shell) ===");
        console2.log("export SEADROP=%s", address(seaDrop));
        console2.log("export NFT=%s", address(nft));
    }
}
