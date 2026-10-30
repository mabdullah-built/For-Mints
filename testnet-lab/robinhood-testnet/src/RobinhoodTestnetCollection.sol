// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// UNVERIFIED / UNCOMPILED: authored without a local `forge` toolchain
// available. Read and `forge build` this yourself before deploying
// anything. Deliberately adds no behavior beyond the real, upstream
// ERC721SeaDrop it subclasses -- the whole point of this lab is to
// validate Kairox against the *real* SeaDrop protocol, not a
// reimplementation of it.

import {ERC721SeaDrop} from "seadrop/ERC721SeaDrop.sol";

/// A tiny, disposable ERC721SeaDrop collection for Robinhood Chain
/// Testnet acceptance testing only. Max supply and stage configuration
/// are set separately (see `script/DeployLab.s.sol`), matching how a real
/// operator would configure any ERC721SeaDrop collection -- this contract
/// itself carries no testnet-specific logic.
contract RobinhoodTestnetCollection is ERC721SeaDrop {
    constructor(
        string memory name_,
        string memory symbol_,
        address[] memory allowedSeaDrop_
    ) ERC721SeaDrop(name_, symbol_, allowedSeaDrop_) {}
}
