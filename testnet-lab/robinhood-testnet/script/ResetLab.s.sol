// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// UNVERIFIED / UNCOMPILED -- see the header comment in DeployLab.s.sol;
// the same caveats apply here. Verify every function signature against
// the actual installed `lib/seadrop` source before running.

import {Script, console2} from "forge-std/Script.sol";
import {SeaDrop} from "seadrop/SeaDrop.sol";
import {PublicDrop} from "seadrop/lib/SeaDropStructs.sol";
import {RobinhoodTestnetCollection} from "../src/RobinhoodTestnetCollection.sol";

/// Reconfigures an already-deployed lab collection's public stage (e.g. to
/// reschedule a fresh future start time for another timed T=0 test run)
/// without redeploying anything. Reads the already-deployed `SEADROP` and
/// `NFT` addresses from the environment -- never invents or guesses them.
///
/// Hard-guarded to Robinhood Chain Testnet (46630) ONLY, identically to
/// DeployLab.s.sol. Never falls back to 4663 or any other chain.
contract ResetLab is Script {
    uint256 constant ROBINHOOD_TESTNET_CHAIN_ID = 46630;
    uint16 constant PUBLIC_WALLET_LIMIT = 2;

    function run() external {
        require(
            block.chainid == ROBINHOOD_TESTNET_CHAIN_ID,
            "ABORT: connected chain is not Robinhood Chain Testnet (46630). Refusing to reconfigure anything."
        );

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address seaDrop = vm.envAddress("SEADROP");
        address nft = vm.envAddress("NFT");
        uint256 publicStageStart = vm.envOr("PUBLIC_STAGE_START", block.timestamp + 1 hours);

        vm.startBroadcast(deployerKey);

        PublicDrop memory publicDrop = PublicDrop({
            mintPrice: 0,
            startTime: uint48(publicStageStart),
            endTime: uint48(publicStageStart + 7 days),
            maxTotalMintableByWallet: PUBLIC_WALLET_LIMIT,
            feeBps: 0,
            restrictFeeRecipients: false
        });
        RobinhoodTestnetCollection(nft).updatePublicDrop(seaDrop, publicDrop);

        vm.stopBroadcast();

        console2.log("Public stage rescheduled, starts at:", publicStageStart);
    }
}
