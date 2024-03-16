// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Params } from "./utilities/Params.sol";
import { SnarkCommon } from "./crypto/SnarkCommon.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { EmptyBallotRoots } from "./trees/EmptyBallotRoots.sol";
import { IPoll } from "./interfaces/IPoll.sol";
import { Utilities } from "./utilities/Utilities.sol";
import { IVerifier } from "./interfaces/IVerifier.sol";

/// @title Poll
/// @notice A Poll contract allows voters to submit encrypted messages
/// which can be either votes, key change messages or topup messages.
/// @dev Do not deploy this directly. Use PollFactory.deploy() which performs some
/// checks on the Poll constructor arguments.
/// @dev Integration of automated delegate voting through DelegatorAI.

contract Poll is Params, Utilities, SnarkCommon, Ownable, EmptyBallotRoots, IPoll {
  using SafeERC20 for ERC20;

  /// @notice Whether the Poll has been initialized
  bool internal isInit;

  /// @notice The coordinator's public key
  PubKey public coordinatorPubKey;

  /// @notice Hash of the coordinator's public key
  uint256 public immutable coordinatorPubKeyHash;

  /// @notice the state root of the state merkle tree
  uint256 public mergedStateRoot;

  // The timestamp of the block at which the Poll was deployed
  uint256 internal immutable deployTime;

  // The duration of the polling period, in seconds
  uint256 internal immutable duration;

  /// @notice Whether the MACI contract's stateAq has been merged by this contract
  bool public stateAqMerged;

  /// @notice Get the commitment to the state leaves and the ballots. This is
  /// hash3(stateRoot, ballotRoot, salt).
  /// Its initial value should be
  /// hash(maciStateRootSnapshot, emptyBallotRoot, 0)
  /// Each successful invocation of processMessages() should use a different
  /// salt to update this value, so that an external observer cannot tell in
  /// the case that none of the messages are valid.
  uint256 public currentSbCommitment;

  /// @notice The number of messages that have been published
  uint256 public numMessages;

  /// @notice The number of signups that have been processed
  /// before the Poll ended (stateAq merged)
  uint256 public numSignups;

  /// @notice Max values for the poll
  MaxValues public maxValues;

  /// @notice Depths of the merkle trees
  TreeDepths public treeDepths;

  /// @notice The contracts used by the Poll
  ExtContracts public extContracts;

  /// @notice the hash of the embedding of the vote context
  /// Assumed to be correctly computed
  /// SHOULD BE VERIFIED USING A EMBEDDING CONVERTER
  uint256 public voteContextHash;

  /// @notice Delegator automated voting information by public key
  /// @dev to be removed with a hash of the merkle tree of votes
  mapping(address => DelegatorAI) public delegatorVotes;

  /// @notice Structure for holding Delegator automated voting information
  struct DelegatorAI {
    uint256 encVote; // Encrypted and salted vote to the User Public Key
    uint256 hasPersonallyVoted; // 1 if the user has voted themselves, otherwise 0
  }

  /// @notice Contract to verify delegator votes using zk-SNARKs
  IVerifier public automatedVoteVerifier;

  error VotingPeriodOver();
  error VotingPeriodNotOver();
  error PollAlreadyInit();
  error TooManyMessages();
  error MaciPubKeyLargerThanSnarkFieldSize();
  error StateAqAlreadyMerged();
  error StateAqSubtreesNeedMerge();
  error InvalidBatchLength();

  event PublishMessage(Message _message, PubKey _encPubKey);
  event TopupMessage(Message _message);
  event MergeMaciStateAqSubRoots(uint256 _numSrQueueOps);
  event MergeMaciStateAq(uint256 _stateRoot, uint256 _numSignups);
  event MergeMessageAqSubRoots(uint256 _numSrQueueOps);
  event MergeMessageAq(uint256 _messageRoot);

  /// @notice Each MACI instance can have multiple Polls.
  /// When a Poll is deployed, its voting period starts immediately.
  /// @param _duration The duration of the voting period, in seconds
  /// @param _voteContextHash The hash of the embedding of the vote context
  /// @param _maxValues The maximum number of messages and vote options
  /// @param _treeDepths The depths of the merkle trees
  /// @param _coordinatorPubKey The coordinator's public key
  /// @param _extContracts The external contracts
  constructor(
    uint256 _duration,
    uint256 _voteContextHash,
    address _automatedVoteVerifier,
    MaxValues memory _maxValues,
    TreeDepths memory _treeDepths,
    PubKey memory _coordinatorPubKey,
    ExtContracts memory _extContracts
  ) payable {
    // check that the coordinator public key is valid
    if (_coordinatorPubKey.x >= SNARK_SCALAR_FIELD || _coordinatorPubKey.y >= SNARK_SCALAR_FIELD) {
      revert MaciPubKeyLargerThanSnarkFieldSize();
    }

    // save the vote context hash
    voteContextHash = _voteContextHash;

    // setup the automated vote verifier
    automatedVoteVerifier = IVerifier(_automatedVoteVerifier);

    // store the pub key as object then calculate the hash
    coordinatorPubKey = _coordinatorPubKey;
    // we hash it ourselves to ensure we store the correct value
    coordinatorPubKeyHash = hashLeftRight(_coordinatorPubKey.x, _coordinatorPubKey.y);
    // store the external contracts to interact with
    extContracts = _extContracts;
    // store duration of the poll
    duration = _duration;
    // store max values
    maxValues = _maxValues;
    // store tree depth
    treeDepths = _treeDepths;
    // Record the current timestamp
    deployTime = block.timestamp;
  }

  /// @notice A modifier that causes the function to revert if the voting period is
  /// not over.
  modifier isAfterVotingDeadline() {
    uint256 secondsPassed = block.timestamp - deployTime;
    if (secondsPassed <= duration) revert VotingPeriodNotOver();
    _;
  }

  /// @notice A modifier that causes the function to revert if the voting period is
  /// over
  modifier isWithinVotingDeadline() {
    uint256 secondsPassed = block.timestamp - deployTime;
    if (secondsPassed >= duration) revert VotingPeriodOver();
    _;
  }

  /// @notice The initialization function.
  /// @dev Should be called immediately after Poll creation
  /// and messageAq ownership transferred
  function init() public {
    if (isInit) revert PollAlreadyInit();
    // set to true so it cannot be called again
    isInit = true;

    unchecked {
      numMessages++;
    }

    // init messageAq here by inserting placeholderLeaf
    uint256[2] memory dat = [NOTHING_UP_MY_SLEEVE, 0];

    (Message memory _message, PubKey memory _padKey, uint256 placeholderLeaf) = padAndHashMessage(dat, 1); // TODO - why is this done?
    extContracts.messageAq.enqueue(placeholderLeaf);

    emit PublishMessage(_message, _padKey);
  }

  /// @notice Submits and verifies a delegator's vote
  /// @param _currentVote The current vote
  /// @param _currentVoteEnc The encrypted current vote
  /// @param _encVote Encrypted vote
  /// @param _proof zk-SNARK proof
  /// @param userPublicKey User's public key
  function submitAutoDelegatorVote(
    uint256 _encVote,
    uint256[5] calldata _proof,
    address _toVoteFor
  ) external isWithinVotingDeadline {
    // Ensure the delegator is registered
    require(extContracts.maci.getDelegatorEmbdeingHashes(_toVoteFor) != 0, "Delegator not registered");

    uint256 delegatorHash = extContracts.maci.getDelegatorEmbdeingHashes(_toVoteFor);

    DelegatorAI storage delegator = delegatorVotes[_toVoteFor];

    // Prevent voting when original user has voted
    require(delegator.hasPersonallyVoted == 0, "Real user has already voted");

    // Verification logic...
    require(
      automatedVoteVerifier.verify(_proof, _encVote, voteContextHash, delegator.embeddingHash, userPublicKey),
      "Vote verification failed"
    );

    // Record the vote
    delegator.encVote = _encVote;
  }

  function getHashOfEncVotes() public view returns (uint256) {
    bytes32 hashChain = keccak256(abi.encodePacked("")); // Initialize hash chain with an empty seed

    for (uint256 i = 0; i < extContracts.maci.withDelegators.length; i++) {
      PubKey memory pubKey = extContracts.maci.withDelegators[i];
      uint256 pubKeyHash = hashPubKey(pubKey);

      DelegatorAI memory delegator = delegatorVotes[pubKeyHash];

      // Consider only delegators who have voted
      // And whose owners did not vote
      if (delegator.encVote != 0 && delegator.hasPersonallyVoted == 0) {
        // Chain the hash with the currentVoteEnc
        hashChain = uint256(keccak256(abi.encodePacked(hashChain, delegator.encVote)));
      }
    }

    return hashChain;
  }

  /// @inheritdoc IPoll
  function topup(uint256 stateIndex, uint256 amount) public virtual isWithinVotingDeadline {
    // we check that we do not exceed the max number of messages
    if (numMessages >= maxValues.maxMessages) revert TooManyMessages();

    // cannot realistically overflow
    unchecked {
      numMessages++;
    }

    /// @notice topupCredit is a trusted token contract which reverts if the transfer fails
    extContracts.topupCredit.transferFrom(msg.sender, address(this), amount);

    uint256[2] memory dat = [stateIndex, amount];
    (Message memory _message, , uint256 messageLeaf) = padAndHashMessage(dat, 2);

    extContracts.messageAq.enqueue(messageLeaf);

    emit TopupMessage(_message);
  }

  /// @inheritdoc IPoll
  /// TODO - how does the collusion resistance work? If I am colluded, and I publish a vote, and then publish a change Pbk,
  /// TODO - these are different messages, and are visible that both were sent. Hence can be detected.
  function publishMessage(Message memory _message, PubKey calldata _encPubKey) public virtual isWithinVotingDeadline {
    // Hash the public key to get a unique identifier for the mapping
    uint256 pubKeyHash = hashPubKey(_encPubKey);

    // Mark the delegator as having voted
    delegatorVotes[msg.sender].hasPersonallyVoted = 1;

    // we check that we do not exceed the max number of messages
    if (numMessages >= maxValues.maxMessages) revert TooManyMessages();

    // validate that the public key is valid
    if (_encPubKey.x >= SNARK_SCALAR_FIELD || _encPubKey.y >= SNARK_SCALAR_FIELD) {
      revert MaciPubKeyLargerThanSnarkFieldSize();
    }

    // cannot realistically overflow
    unchecked {
      numMessages++;
    }

    // we enforce that msgType here is 1 so we don't need checks
    // at the circuit level
    _message.msgType = 1;

    uint256 messageLeaf = hashMessageAndEncPubKey(_message, _encPubKey);
    extContracts.messageAq.enqueue(messageLeaf);

    emit PublishMessage(_message, _encPubKey);
  }

  /// @notice submit a message batch
  /// @dev Can only be submitted before the voting deadline
  /// @param _messages the messages
  /// @param _encPubKeys the encrypted public keys
  function publishMessageBatch(Message[] calldata _messages, PubKey[] calldata _encPubKeys) external {
    if (_messages.length != _encPubKeys.length) {
      revert InvalidBatchLength();
    }

    uint256 len = _messages.length;
    for (uint256 i = 0; i < len; ) {
      // an event will be published by this function already
      publishMessage(_messages[i], _encPubKeys[i]);

      unchecked {
        i++;
      }
    }
  }

  /// @inheritdoc IPoll
  function mergeMaciStateAqSubRoots(uint256 _numSrQueueOps, uint256 _pollId) public onlyOwner isAfterVotingDeadline {
    // This function cannot be called after the stateAq was merged
    if (stateAqMerged) revert StateAqAlreadyMerged();

    // merge subroots
    extContracts.maci.mergeStateAqSubRoots(_numSrQueueOps, _pollId);

    emit MergeMaciStateAqSubRoots(_numSrQueueOps);
  }

  /// @inheritdoc IPoll
  function mergeMaciStateAq(uint256 _pollId) public onlyOwner isAfterVotingDeadline {
    // This function can only be called once per Poll after the voting
    // deadline
    if (stateAqMerged) revert StateAqAlreadyMerged();

    // set merged to true so it cannot be called again
    stateAqMerged = true;

    // the subtrees must have been merged first
    if (!extContracts.maci.stateAq().subTreesMerged()) revert StateAqSubtreesNeedMerge();

    mergedStateRoot = extContracts.maci.mergeStateAq(_pollId);

    // Set currentSbCommitment
    uint256[3] memory sb;
    sb[0] = mergedStateRoot;
    sb[1] = emptyBallotRoots[treeDepths.voteOptionTreeDepth - 1];
    sb[2] = uint256(0);

    currentSbCommitment = hash3(sb);

    numSignups = extContracts.maci.numSignUps();
    emit MergeMaciStateAq(mergedStateRoot, numSignups);
  }

  /// @inheritdoc IPoll
  function mergeMessageAqSubRoots(uint256 _numSrQueueOps) public onlyOwner isAfterVotingDeadline {
    extContracts.messageAq.mergeSubRoots(_numSrQueueOps);
    emit MergeMessageAqSubRoots(_numSrQueueOps);
  }

  /// @inheritdoc IPoll
  function mergeMessageAq() public onlyOwner isAfterVotingDeadline {
    uint256 root = extContracts.messageAq.merge(treeDepths.messageTreeDepth);
    emit MergeMessageAq(root);
  }

  /// @inheritdoc IPoll
  function getDeployTimeAndDuration() public view returns (uint256 pollDeployTime, uint256 pollDuration) {
    pollDeployTime = deployTime;
    pollDuration = duration;
  }

  /// @inheritdoc IPoll
  function numSignUpsAndMessages() public view returns (uint256 numSUps, uint256 numMsgs) {
    numSUps = numSignups;
    numMsgs = numMessages;
  }
}
