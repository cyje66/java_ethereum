// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;

import "./EC.sol";
import "./DateTime.sol";

contract Owned {
    address owner;
    bytes32 androidRpId;
    bytes32 iosRpId;
    constructor() public {
        owner = msg.sender;
        androidRpId = 0xf226a3581336eddc2fea8ee01adc4bf91105725cfb4ce0650955005002d7042f;
        iosRpId = 0x42582e08c0007c93b1a9800aabe83dd42d815eeeb7ded4e302e616cf0609e197;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}
contract AccessControl is Owned, EllipticCurve, DateTime {
    struct status{
        //struct for account status
        address eth_address;
        uint[2] pubk;
        string name;
        bytes32 clientDataHash;
        uint validationTime;
        bool status_for_com;        // true or false
        string status_for_people;   // valid, suspend or delete
    }
    struct checklist{
        //struct for systematic check
        bool isCreated;
        bool isSuspended;
        bool isGranted;
        bool isTerminated;
    }
    enum AssertionVerificationResult{
        success,
        clientDataErr,
        ethUserErr,
        signatureErr,
        rpErr
    }
    event AccountCreated(string indexed _accountID, string _name, uint256 indexed _time);
    event AccountGranted(string indexed _accountID, uint256 indexed _time);
    event AccountTerminated(string indexed _accountID, uint256 indexed _time);
    event AccountSuspended(string indexed _accountID, uint256 indexed _time);
    event AccountResumed(string indexed _accountID, uint256 indexed _time);
    event SignatureValidated(string indexed _accountID, bytes32 message, uint[2] rs, uint[2] indexed pubk, AssertionVerificationResult result, uint256 indexed _time);
    event EthAddressStored(string indexed _accountID, address indexed addr, uint256 _time);
    event SetGrantAddrPubkey(string indexed _accountID, address indexed addr, uint[2] indexed pk, uint256 _time);
    event PubkeyStored(string indexed _accountID, uint[2] indexed pk, uint256 _time);
    event AssertionRequest(string indexed _accountID, bytes32 indexed _clientDataHash, uint256 _time);
    // map每個帳號位址的狀態
    mapping (string => status) user;
    mapping (string => checklist) user_check;

    // 設置帳號並給予預設值
    function create_Account(string memory _accountID ,string memory _name) onlyOwner public {
        require(user_check[_accountID].isCreated == false);
        require(user_check[_accountID].isTerminated == false);

        user[_accountID].name = _name;
        user[_accountID].status_for_com = false;
        user[_accountID].status_for_people ='invalid';

        user_check[_accountID].isCreated = true;
        user_check[_accountID].isSuspended = false;
        user_check[_accountID].isGranted = false;
        user_check[_accountID].isTerminated = false;

        emit AccountCreated(_accountID, _name, getCurrentDate());
    }

    function suspend (string memory _accountID) onlyOwner public{
        require(user_check[_accountID].isCreated == true);
        require(user_check[_accountID].isTerminated == false);

        user[_accountID].status_for_com = false;
        user[_accountID].status_for_people ='suspend';

        user_check[_accountID].isSuspended =true;

        emit AccountSuspended(_accountID, getCurrentDate());
    }

    function resume(string memory _accountID) onlyOwner public{
        require(user_check[_accountID].isCreated == true);
        require(user_check[_accountID].isTerminated == false);
        require(user_check[_accountID].isSuspended == true);

        user[_accountID].status_for_com = true;
        user[_accountID].status_for_people = 'valid';

        user_check[_accountID].isSuspended = false;

        emit AccountResumed(_accountID, getCurrentDate());

    }

    function grant (string memory _accountID) onlyOwner public{
        require(user_check[_accountID].isCreated == true);
        require(user_check[_accountID].isTerminated == false);

        user[_accountID].status_for_com = true;
        user[_accountID].status_for_people ='valid';

        user_check[_accountID].isGranted = true;

        emit AccountGranted(_accountID, getCurrentDate());
    }

    function terminate (string memory _accountID) onlyOwner public{
        require(user_check[_accountID].isCreated == true);

        user[_accountID].status_for_com = false;
        user[_accountID].status_for_people ='terminated';

        user_check[_accountID].isTerminated = true;

        emit AccountTerminated(_accountID, getCurrentDate());
    }

    //called when generate assetion request for someone
    function storeClientDataHash(string memory  _accountID, bytes32 _clientDataHash) onlyOwner public {
        require(user_check[_accountID].isCreated == true);
        user[_accountID].clientDataHash = _clientDataHash;

        emit AssertionRequest(_accountID, _clientDataHash, getCurrentDate());
    }
    /**
     * @dev Validate combination of message, signature, and public key.
     */
    function validateSig (string memory  _accountID, bytes32 clientDataHash, bytes memory authData, uint[2] memory rs) public {
        //require(validateSignature(message,  rs, Q) == true);

        if (clientDataHash != user[_accountID].clientDataHash){
            //clientDataErr: 1

            emit SignatureValidated(_accountID, clientDataHash, rs, user[_accountID].pubk, AssertionVerificationResult.clientDataErr, getCurrentDate());
        } else if (msg.sender != user[_accountID].eth_address) {
            //ethUserErr: 2

            emit SignatureValidated(_accountID, clientDataHash, rs, user[_accountID].pubk, AssertionVerificationResult.ethUserErr, getCurrentDate());
        } else if (validateSignature(sha256(abi.encodePacked(sha256(abi.encodePacked(authData, clientDataHash)))), rs, user[_accountID].pubk) == false && validateSignature(sha256(abi.encodePacked(authData, clientDataHash)), rs, user[_accountID].pubk) == false) {
            //signatureErr: 3

            emit SignatureValidated(_accountID, clientDataHash, rs, user[_accountID].pubk, AssertionVerificationResult.signatureErr, getCurrentDate());
        } else if (bytesToBytes32(authData, 0) != androidRpId && bytesToBytes32(authData, 0) != iosRpId ){
            //rpErr: 4

            emit SignatureValidated(_accountID, clientDataHash, rs, user[_accountID].pubk, AssertionVerificationResult.rpErr, getCurrentDate());
        } else{
            //success: 0

            emit SignatureValidated(_accountID, clientDataHash, rs, user[_accountID].pubk, AssertionVerificationResult.success, getCurrentDate());
        }

        // timeout 機制
        user[_accountID].validationTime = getCurrentDate();

    }

    function store_eth_address (string memory _accountID, address addr) onlyOwner public {
        user[_accountID].eth_address = addr;

        emit EthAddressStored(_accountID, addr, getCurrentDate());
    }

    function store_pk (string memory _accountID, uint[2] memory pubk) onlyOwner public {
        user[_accountID].pubk = pubk;

        emit PubkeyStored(_accountID, pubk, getCurrentDate());
    }

    function grant_and_store_pk_eth (string memory _accountID, uint[2] memory pubk, address addr) onlyOwner public {
        require(user_check[_accountID].isTerminated == false);

        user[_accountID].status_for_com = true;
        user[_accountID].status_for_people ='valid';
        user[_accountID].pubk = pubk;
        user[_accountID].eth_address = addr;

        user_check[_accountID].isGranted = true;
        emit SetGrantAddrPubkey(_accountID, addr, pubk, getCurrentDate());

    }

    // turning timestamp into readable datetime
    function getCurrentDate() private view returns (uint256) {
        // current datetime : yyyymmdd
        uint256  YMD;
        uint year = getYear(block.timestamp + 8 hours);
        uint month = getMonth(block.timestamp + 8 hours);
        uint day = getDay(block.timestamp + 8 hours);
        uint hour = getHour(block.timestamp + 8 hours);
        uint minute = getMinute(block.timestamp + 8 hours);
        YMD = year * 100000000 + month * 1000000 + day * 10000 + hour * 100 + minute;
        return YMD;
    }

    function bytesToBytes32(bytes memory b, uint offset) private pure returns (bytes32) {
        bytes32 out;

        for (uint i = 0; i < 32; i++) {
            out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
        }
        return out;
    }
}
