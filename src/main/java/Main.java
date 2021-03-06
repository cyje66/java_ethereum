import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

import contracts.AccessControl;
import contracts.Storage;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.StaticArray2;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.Utils;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.admin.Admin;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.ClientTransactionManager;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.Transfer;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

public class Main {

    public final static String PRIVATE_KEY = "8049d044ef9fd85fadf5a1911a9a422272b9ecd911a0a2b56435f87b237a592b";
    public final static BigInteger GAS_LIMIT = BigInteger.valueOf(6721975L);
//    GAS_PRICE = 20GWei
    public final static BigInteger GAS_PRICE = Convert.toWei("20", Convert.Unit.GWEI).toBigInteger();
    public final static String CONTRACT_ADDRESS = "0xa376f79dce37ed78e8f85540c1254ed2f846aaae";
//    deploy on ganache
    public final static String ACCESSCONTROL_ADDRESS = "0x70ba62137e52a6af26b773facb1d3843e32c265b";
//    deploy on remix:
//    public final static String ACCESSCONTROL_ADDRESS = "0x41959594C5f35a2F591814bC073b901A4afcc832";
    public final static String accountID = "126";
    public final static String admin = "0x2429891e261f9544ffDbE7858B03E92DaF75e5B6";
    public final static String RECIPIENT = "0x326d086558c644E759B8c0eB75dfF4Cc93Ae9cCB";
    public final static List<BigInteger> user1EsPublicKeyArray =
            Arrays.asList(
                    new BigInteger("8b12e8278f7f8b9f7f2f99e04fe57f10fd6a7a52ee0467ca2dceedcbf5c7073c", 16),
                    new BigInteger("023e47fb62178ac37fa6ee7c554357727ca22dd4a953f3522624c623ba6cc911", 16)
            );
    public final static String clientDataHash = "7898e6377059c3f758a0380244f9b45b8ea40777e2eb49d6440f16d934de863c";
    private final static String signedTx = "0xf90166018083895440942c44c7e0d873b138d7e247cd2c146e4f3b73848a80b90104135c695200000000000000000000000000000000000000000000000000000000000002057898e6377059c3f758a0380244f9b45b8ea40777e2eb49d6440f16d934de863c00000000000000000000000000000000000000000000000000000000000000a0cba99b8205cc3aa19a44a2080ec40872b19eb983eb0437d01d7d530fed435751499764db9edb00c6f9165feef83bd6c1685c3035321c580fcbef24b45379cd270000000000000000000000000000000000000000000000000000000000000025685f6a9a4327ab66dfb74b6f22e2fc92f6d11e04c2a5a7930502ff45602e687c05000000010000000000000000000000000000000000000000000000000000001ba0323dd545c7b8e1dc6dfc553086bbc7b84d78c0c3d40f64b2e68f88f04216afd9a0291016e66b3b5c8ff4fa2ae28c278552289fa101a7475f512478b43948998ddc";
    private final static String authData = "499764db9edb00c6f9165feef83bd6c1685c3035321c580fcbef24b45379cd27";

    public static void main(String[] args) {
        // used in deployContract()
        ContractGasProvider provider = new StaticGasProvider(BigInteger.valueOf(20000000000L), BigInteger.valueOf(6721975L));

        try {
            new Main();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Main() throws Exception {
        Web3j web3j = Web3j.build(new HttpService("http://localhost:7545"));
        Credentials credentials = Credentials.create(PRIVATE_KEY);
        Credentials credentials1 = WalletUtils.loadCredentials("123",
                "src/main/resources/keystore/UTC--2021-06-30T10-19-50.856000000Z--df5929ef01c04967fa505e0fbe66bf989f02ff88.json");
        Credentials credentials2 = Credentials.create("6a147b449c90eee8f547561b9ef57e28790bc71cf7900c9d540170cc971e4dc7");
        TransactionManager transactionManager = new RawTransactionManager(
                web3j,
                credentials
        );
        ContractGasProvider provider = new StaticGasProvider(GAS_PRICE, GAS_LIMIT);

//        sendRawTx(web3j, credentials);
//        sendTxWithManager(web3j);
//        sendRawTxWithManager(web3j, credentials);

//        sendTx(web3j);
//        Optional<TransactionReceipt> receipt = web3j.ethGetTransactionReceipt("0x0d6364bf82a788d2f84f2ff1ec582f157d8494d511a78753f5fcbd969ac20cdf")
//                                                    .send()
//                                                    .getTransactionReceipt();
//        System.out.println(receipt);

//        transferEth(web3j, credentials, transactionManager);

//      load Storage contract
        Storage storage = loadStorageContract(CONTRACT_ADDRESS, web3j, credentials);
        printWeb3Version(web3j);
//        TransactionReceipt transactionReceipt = storage.store(BigInteger.valueOf(100))
//                                                        .send();
//        System.out.println(transactionReceipt);
//        BigInteger num = storage.retrieve().send();
//        System.out.println("num: " + num);

//      load AccessControl contract
        AccessControl accessControl = loadAccessControl(ACCESSCONTROL_ADDRESS, web3j, credentials, provider);
//        createAccount(accessControl);
//        grantAccount(web3j, accessControl, accountID, user1EsPublicKeyArray, RECIPIENT);
//        terminate(accessControl, accountID);
//        storeClientDataHash(accessControl, accountID, decodeUsingBigInteger(clientDataHash));
        System.out.println("byte:" + Arrays.toString(decodeHexString("7898e6377059c3f758a0380244f9b45b8ea40777e2eb49d6440f16d934de863c")));

        BigInteger nonce = web3j.ethGetTransactionCount(admin, DefaultBlockParameterName.LATEST).send().getTransactionCount();
        System.out.println(nonce);

        sendSignTx(web3j, credentials2, accessControl);

//        storeEthAddress();
//        storeEC256PubKey(web3j, accessControl, accountID, user1EsPublicKeyArray);
//        accessControl.validateSig(accountID)

        EthFilter filter = new EthFilter(
                DefaultBlockParameterName.EARLIEST,
                DefaultBlockParameterName.LATEST,
                accessControl.getContractAddress()
        ).addSingleTopic("0x44d95adff991b8444cd1878c0022cd2129ad7ea5f01b31f1acc45d7d69ca87dc");
//         .addOptionalTopics(String.valueOf(web3j.web3Sha3("125")));
        accessControl.accountCreatedEventFlowable(filter).subscribe(log -> {
            System.out.println(log._name);
        });

    }

    private void sendSignTx(Web3j web3j, Credentials credentials2, AccessControl accessControl) throws IOException, InterruptedException, java.util.concurrent.ExecutionException {
        // Create the Transaction
        RawTransaction rawTransaction = RawTransaction.createTransaction(
                getNonce(web3j, credentials2.getAddress()),
                GAS_PRICE,
                GAS_LIMIT,
                ACCESSCONTROL_ADDRESS,
                accessControl.validateSig(accountID,
                        decodeHexString(clientDataHash),
                        decodeHexString(authData),
                        user1EsPublicKeyArray).encodeFunctionCall()
        );
        // Sign the Transaction
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials2);

        String hexValue = Numeric.toHexString(signedMessage);
        System.out.println("hexValue: " + hexValue);

        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).sendAsync().get();
        String txHash = ethSendTransaction.getTransactionHash();
//        Response.Error error = ethSendTransaction.getError();
        System.out.println(txHash);
        TransactionReceipt receipt = web3j.ethGetTransactionReceipt(txHash)
                                                    .send()
                                                    .getTransactionReceipt()
                                                    .get();
        List<Log> logs = receipt.getLogs();
        int length = logs.get(0).getData().length();
        String data = logs.get(0).getData();
        int status = Integer.parseInt(data.substring(length -1), 10);
        String statusMap[] =
                {
                    "Authentication success",
                    "Client data authentication failed",
                    "User authentication failed",
                    "Signature format failed",
                    "relying party authentication failed"
                };
        System.out.println(status);
        System.out.println(statusMap[status]);
    }

    public byte[] decodeHexString(String hexString) {
        byte[] byteArray = new BigInteger(hexString, 16)
                .toByteArray();
        if (byteArray[0] == 0) {
            byte[] output = new byte[byteArray.length - 1];
            System.arraycopy(
                    byteArray, 1, output,
                    0, output.length);
            return output;
        }
        return byteArray;
    }

    private void storeEC256PubKey(Web3j web3j, AccessControl accessControl, String accountID, List<BigInteger> pubk) throws IOException {
        String data = accessControl.store_pk(accountID, pubk).encodeFunctionCall();
        System.out.println("encoded function: " + data);

        Transaction transaction = Transaction.createFunctionCallTransaction(
                admin,
                null,
                GAS_PRICE,
                GAS_LIMIT,
                ACCESSCONTROL_ADDRESS,
                data);
        String transactionHash = web3j.ethSendTransaction(transaction).send().getTransactionHash();
        Optional<TransactionReceipt> transactionReceipt = web3j.ethGetTransactionReceipt(transactionHash)
                .send()
                .getTransactionReceipt();
        System.out.println(transactionReceipt);
    }


    private void grantAccount(Web3j web3j, AccessControl accessControl, String accountId, List<BigInteger> pubk, String address) throws IOException {
//        encode the function, i.e. make a tx object
        String data = accessControl.grant_and_store_pk_eth(
                accountId,
                pubk,
                address
        ).encodeFunctionCall();
        System.out.println("encoded function: " + data);

        Transaction transaction = Transaction.createFunctionCallTransaction(
                admin,
                null,
                GAS_PRICE,
                GAS_LIMIT,
                ACCESSCONTROL_ADDRESS,
                data);
        String transactionHash = web3j.ethSendTransaction(transaction).send().getTransactionHash();
        Optional<TransactionReceipt> transactionReceipt = web3j.ethGetTransactionReceipt(transactionHash)
                                                               .send()
                                                               .getTransactionReceipt();
        System.out.println(transactionReceipt);
    }

    /*contract functions*/

    private void createAccount(AccessControl accessControl, String accountId, String name) throws Exception {
        TransactionReceipt transactionReceipt = accessControl.create_Account(accountId, name).send();
        System.out.println(transactionReceipt);
    }

    private void terminate(AccessControl accessControl, String accountId) throws Exception {
        TransactionReceipt transactionReceipt = accessControl.terminate(accountId).send();
        System.out.println(transactionReceipt);
    }

    private void storeClientDataHash(AccessControl accessControl, String accountId, byte[] clientDataHash) throws Exception {
        TransactionReceipt transactionReceipt = accessControl.storeClientDataHash(accountId, clientDataHash).send();
        System.out.println(transactionReceipt);
    }

    private void storeEthAddress(AccessControl accessControl, String accountId, String address) throws Exception {
        TransactionReceipt transactionReceipt = accessControl.store_eth_address(accountId, address).send();
        System.out.println(transactionReceipt);
    }

    private AccessControl loadAccessControl(String contractAddress, Web3j web3j, Credentials credentials, ContractGasProvider provider) {
        return AccessControl.load(contractAddress,
                web3j,
                credentials,
                provider
                );
    }

    private String deployAccessControl(Web3j web3j, TransactionManager transactionManager, ContractGasProvider provider) throws Exception {
        return AccessControl.deploy(web3j, transactionManager, provider)
                                                    .send()
                                                    .getContractAddress();
    }

    /*miscellaneous functions*/

    //    ????????????credential???????????????????????????????????????????????????????????????
    private void sendRawTxWithManager(Web3j web3j, Credentials credentials) throws Exception {
        String account2 = web3j.ethAccounts().send().getAccounts().get(1);
        BigDecimal value = BigDecimal.valueOf(1L);
        RawTransactionManager rtm = new RawTransactionManager(web3j, credentials);
        Transfer transfer = new Transfer(web3j, rtm);
        TransactionReceipt receipt = transfer.sendFunds(account2, value, Convert.Unit.ETHER).send();
        System.out.println(receipt);
    }

//    ?????????credential??????????????????account??????????????????????????????
    private void sendTxWithManager(Web3j web3j) throws Exception {
        List<String> account = web3j.ethAccounts().send().getAccounts();
        String account1 = account.get(0);
        String account2 = account.get(1);
        BigDecimal value = BigDecimal.valueOf(1L);
        ClientTransactionManager ctm = new ClientTransactionManager(web3j, account1);
        Transfer transfer = new Transfer(web3j, ctm);
        TransactionReceipt receipt = transfer.sendFunds(account2, value, Convert.Unit.ETHER).send();
        System.out.println(receipt);
    }

    private void sendRawTx(Web3j web3j, Credentials credentials) throws IOException {
        List<String> account = web3j.ethAccounts().send().getAccounts();
        String account1 = account.get(0);
        String account2 = account.get(1);
        BigInteger value = Convert.toWei("1", Convert.Unit.ETHER).toBigInteger();
        String data = "";
        BigInteger nonce = getNonce(web3j, credentials.getAddress());
        RawTransaction rawTx = RawTransaction.createTransaction(nonce, GAS_PRICE, GAS_LIMIT, account2, data);
//        sign rawTx
        byte[] signedMessage = TransactionEncoder.signMessage(rawTx, credentials);
        String hexValue = Numeric.toHexString(signedMessage);
        System.out.println("hexValue: " + hexValue);
        String txHash = web3j.ethSendRawTransaction(hexValue).send().getTransactionHash();
        System.out.println("raw tx: " + txHash);
    }

    private BigInteger getNonce(Web3j web3j, String account) throws IOException {
        return web3j.ethGetTransactionCount(account, DefaultBlockParameterName.LATEST)
                                .send().getTransactionCount();
    }

    private void sendTx(Web3j web3j) throws IOException {
        List<String> account = web3j.ethAccounts().send().getAccounts();
        String account1 = account.get(0);
        String account2 = account.get(1);
        BigInteger value = BigInteger.valueOf(1000000000000000000L);
        BigInteger nonce = null;
        String data = "Hello there!";
        Transaction tx = new Transaction(account1, nonce, GAS_PRICE, GAS_LIMIT, account2, value, data);
        String txHash = web3j.ethSendTransaction(tx).send().getTransactionHash();
        System.out.println(txHash);
    }

    private void generateWalletFile() throws CipherException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        String password = "123";
        File destDir = new File("src/main/resources/keystore");
        String fn = WalletUtils.generateNewWalletFile(password, destDir, true);
    }

    //    transfer 1 eth to RECIPIENT
    private void transferEth(Web3j web3j, Credentials credentials, TransactionManager transactionManager, String recipient) throws Exception {
        Transfer transfer = new Transfer(web3j, transactionManager);
        TransactionReceipt transactionReceipt = Transfer.sendFunds(
                web3j,
                credentials,
                recipient,
                BigDecimal.valueOf(1.0),
                Convert.Unit.ETHER
        ).send();
    }

    private void printWeb3Version(Web3j web3j) {
        Web3ClientVersion web3ClientVersion = null;
        try {
            web3ClientVersion = web3j.web3ClientVersion().send();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String web3ClientVersionString = null;
        if (web3ClientVersion != null) {
            web3ClientVersionString = web3ClientVersion.getWeb3ClientVersion();
        }
        System.out.println("web3 client version: "+ web3ClientVersionString);
    }

    private String deployStorageContract(Web3j web3j, TransactionManager transactionManager, ContractGasProvider contractGasProvider) throws Exception {
        return Storage.deploy(web3j, transactionManager, contractGasProvider)
                .send()
                .getContractAddress();
    }

    private Storage loadStorageContract(String contractAddress, Web3j web3j, Credentials credentials) {
        return Storage.load(contractAddress, web3j, credentials, GAS_PRICE, GAS_LIMIT);
    }
}
