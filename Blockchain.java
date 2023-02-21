import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;

public class Blockchain {

    static int PROCESS_ID;
    static boolean PROCESS_STARTED = false;
    static boolean EXIT = false;
    static Map<UUID, Block> blockChainMap = new HashMap<>();
    static List<Block> listBlock = new ArrayList<>();

    static Map<Integer, String> mapActiveProcess = new HashMap<>();

    static String masterProcessAddress = "";

    public Comparator<Block> BlockComparator = (b1, b2) -> {
        if (b1.timeStampCreation == b2.timeStampCreation) return 0;
        else if (b1.timeStampCreation == null) return -1;
        else if (b2.timeStampCreation == null) return 1;
        return b1.timeStampCreation.compareTo(b2.timeStampCreation);
    };

    final PriorityBlockingQueue<Block> priorityQueue = new PriorityBlockingQueue<>(100, BlockComparator);

    public static void main(String[] args) {
        PROCESS_ID = args.length > 0 ? Integer.parseInt(args[0]) : 0;

        if (PROCESS_ID > 0) masterProcessAddress = args.length == 2 ? args[1] : "";

        Logger.log(String.format("Initializing process (Process ID : %s)", PROCESS_ID),PROCESS_ID);

        Blockchain bc = new Blockchain();
        if (Blockchain.PROCESS_ID == 0) bc.startNodeManagerServers();
        if(bc.registerProcess()){
            bc.startServers();
            if (PROCESS_ID == Utility.PROCESS_COUNT - 1 && !PROCESS_STARTED) {
                EventManager.broadCastDummyBlock();
                EventManager.triggerProcessExecution();
            }
            if(Blockchain.PROCESS_STARTED) EventManager.broadcastKeys();
            EventManager.manageClientRequest();
        }
    }

    /**
     * Servers to manage Processes/Nodes registration and status
     */
    public void startNodeManagerServers(){
        ThreadPool.getService().execute(new NodeRegisterServer());
        ThreadPool.getService().execute(new ActiveNodeServer());
        ThreadPool.getService().execute(new ProcessStatusServer());
    }

    /**
     * Servers to manage blockchain processing
     */
    public void startServers() {
        ThreadPool.getService().execute(new PublicKeyServer());
        ThreadPool.getService().execute(new KeyServer());
        ThreadPool.getService().execute(new UVBlockServer(priorityQueue));
        ThreadPool.getService().execute(new BlockchainServer());
        ThreadPool.getService().execute(new UVBlockVerification(priorityQueue));
        ThreadPool.getService().execute(new TriggerProcessServer(priorityQueue));
        ThreadPool.getService().execute(new InvalidBlockServer());
    }

    /**
     * Trigger registration request for process
     * @return
     */
    public boolean registerProcess() {
        return EventManager.registerProcess(true);
    }
}

/**
 * Block POJO object
 */
class Block implements Serializable{
    public UUID uuid;
    public String hashData;
    public String previousHash;
    public String data;
    public String timeStampCreation;
    public String timeStampVerify;
    public int blockNo;
    public int processId;
    public String signedUUID;
    public String signedData;
    public String hash;
    public String signedHash;
    public int verificationProcess;
    public String randomSeed;
    public String aesKey;
    public String blockProcessID;

    Block(String inData) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        uuid = UUID.randomUUID();
        data = inData;
        timeStampCreation = String.valueOf(new Date().getTime());
        processId = Blockchain.PROCESS_ID;
        hashData = HashUtility.getHashValue(data);
        signedUUID = getSignedRSA(uuid.toString());
        signedData = getSignedRSA(data);
        blockNo = 0;
        aesKey = getSignedSecretKey();
    }

    private String getSignedRSA(String data) {
        return KeyGeneratorUtil.signData(data, KeyGeneratorUtil.getPrivateKey());
    }

    /**
     * Encrypt given data using AES key
     * @param data
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    private String getSignedAES(String data) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return CipherHandler.encryptAES(data, KeyGeneratorUtil.getSecretKey());
    }

    /**
     * Encrypt AES secret key using RSA private key
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public String getSignedSecretKey() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return CipherHandler.encryptRSA(KeyGeneratorUtil.getSecretKey().getEncoded(), KeyGeneratorUtil.getPrivateKey());
    }

    public String getBlockData(){
        return data + blockNo + processId + previousHash + timeStampCreation + verificationProcess + timeStampVerify + randomSeed + uuid.toString();
    }

    /**
     * Get winning hash from previous block as previous hash
     * @param list
     * @return
     */
    public String getPreviousHash(List<Block> list){
        return list.size() > 0 ? list.get(list.size()-1).hashData : "";
    }
}

/**
 * EventManager class to manage
 */
class EventManager {

    /**
     * Return list of current active processes along with their IPAddress
     * @return
     */
    private static Map<Integer, String> getActiveProcessMap() {
        Socket socket = SocketHandler.getSocket(Utility.getMasterAddress(), Ports.ActiveNodes);
        try {
            String blockString = SocketHandler.readAsJson(socket);
            Map<Integer, String> map = JsonHandler.getGson().fromJson(blockString, new TypeToken<Map<Integer, String>>(){}.getType());
            socket.close();
            return map;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sends request to registration server to request current process as active process
     * @param isRegister
     * @return
     */
    public static boolean registerProcess(boolean isRegister) {
        try {
            Socket socket = SocketHandler.getSocket(Utility.getMasterAddress(), Ports.NodeRegister);

            if(socket == null) {
                Logger.log("Not able to register as root server(Process 0) is not up. Make sure Process 0 is up and running...!!!",Blockchain.PROCESS_ID);
                Logger.log("If Process 0 is not running on current machine, please provie IPAddress of Process 0 as second argument...!!!",Blockchain.PROCESS_ID);
                return false;
            }

            Logger.log("Sending request to registration server...!!!", Blockchain.PROCESS_ID);
            SocketHandler.getOutputStream(socket).writeObject(new Register(isRegister));
            Register register = (Register) SocketHandler.getInputStream(socket).readObject();

            if(isRegister){
                Logger.log(register.responseMessage, Blockchain.PROCESS_ID);
                if(register.isRegister) {
                    Blockchain.PROCESS_STARTED = register.isProcessRunning;
                    if (Blockchain.PROCESS_STARTED) loadBlockChain(register);
                }
                else {
                    ClientRequestManager.closeAllActiveProcess();
                    System.exit(200);
                }
            }
            socket.close();
            return true;
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Broadcast public keys to all active Process/Nodes in the network
     */
    public static void broadcastKeys(){
        Logger.log(String.format("Broadcasting Public key to all servers...!!!"),Blockchain.PROCESS_ID);
        try {

            getActiveProcessMap().forEach((id,address) -> {
                try {
                    Socket socket = SocketHandler.getSocket(address, Ports.getCurrentPort(Ports.PublicKey, id));
                    if(socket == null) {
                        Logger.log(String.format("Key server is not up for Process_#%s on port %s...!!!",id,Ports.getCurrentPort(Ports.PublicKey, id)),Blockchain.PROCESS_ID);
                    } else {
                        SocketHandler.getOutputStream(socket).writeObject(new KeyData(Blockchain.PROCESS_ID, KeyGeneratorUtil.getPublicKey()));
                        socket.close();
                    }
                } catch (IOException e) {
                    Logger.log("Error occurred while broadcasting Public keys...!!!", Blockchain.PROCESS_ID);
                    throw new RuntimeException(e);
                }

            });
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Load data from input text file and create Unverified blocks
     * @param filename
     */
    public static void loadUVBlock(String filename){
        try {
            int count = 0;
            for(String obj : InputHandler.readInput(!filename.isEmpty() ? filename : Utility.INPUT_FILENAME)) {
                Block block = new Block(obj);
                block.blockProcessID = Blockchain.PROCESS_ID + "_" + (++count);
                broadcastUVBlock(block);
            }
            Logger.log(String.format("%s blocks have been added to unverified blocks queue for verification...!!!", count),Blockchain.PROCESS_ID);
            Thread.sleep(2000);
        } catch (InterruptedException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    /**
     * Broadcast verified blocks to all active process/nodes in network
     * @param block
     */
    public static void broadcastVerifiedBlock(Block block){
        Logger.log(String.format("Broadcasting Verified block no %s to all servers...!!!", block.blockNo),Blockchain.PROCESS_ID);
        getActiveProcessMap().forEach((id,address) -> {
            try {
                Socket socket = SocketHandler.getSocket(address, Ports.getCurrentPort(Ports.Blockchain,id));
                if(socket == null) {
                    Logger.log(String.format("Blockchain server is not up for Process_#%s on port %s...!!!",id,Ports.getCurrentPort(Ports.Blockchain, id)),Blockchain.PROCESS_ID);
                } else {
                    SocketHandler.writeAsJson(socket, JsonHandler.toJson(block));
                    socket.close();
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Broadcast unverified blocks to all active process/nodes in the network
     * @param block
     */
    public static void broadcastUVBlock(Block block) {
        Logger.log("Broadcasting Unverified block to all servers...!!!",Blockchain.PROCESS_ID);
        getActiveProcessMap().forEach((id,address) -> {
            try {
                Socket socket = SocketHandler.getSocket(address, Ports.getCurrentPort(Ports.UVBlock, id));
                if(socket == null) {
                    Logger.log(String.format("UVBlock server is not up for Process_#%s on port %s...!!!",id,Ports.getCurrentPort(Ports.UVBlock, id)),Blockchain.PROCESS_ID);
                } else {
                    SocketHandler.writeAsJson(socket, JsonHandler.toJson(block));
                    socket.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Once Process 2 starts, it triggers the blockchain processing in all the active processes
     */
    public static void triggerProcessExecution() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        getActiveProcessMap().forEach((id,address) -> {
                try {
                    Socket socket = SocketHandler.getSocket(address, Ports.getCurrentPort(Ports.TriggerProcess, id));
                    SocketHandler.getOutputStream(socket).write(id);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });

    }

    /**
     * Reset blockchain from specified  block and sends notification to all the active nodes in the network
     * @param block
     */
    public static void resetBlockChain(Block block) {

        getActiveProcessMap().forEach((id,address) -> {
            try {
                Socket socket = SocketHandler.getSocket(address, Ports.getCurrentPort(Ports.InvalidBlock, id));
                if (socket == null) {
                    Logger.log(String.format("Invalid block server is not up for Process_#%s on port %s...!!!", id, Ports.getCurrentPort(Ports.InvalidBlock, id)), Blockchain.PROCESS_ID);
                } else {
                    SocketHandler.writeAsJson(socket, JsonHandler.toJson(block));
                    socket.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Manage adhoc requests through CLI inputs from user
     */
    public static void manageClientRequest() {
        try {
            boolean noexit=true;
            while (noexit){
                Logger.console("Please select appropriate input : ");
                Logger.console(" 1. 'C' Credit Loop");
                Logger.console(" 2. 'R' Read Loop");
                Logger.console(" 3. 'V' Verify Block Chain ('HASH','SIGNEDUUID','SIGNNEDDATA','SIGNEDEDHASH','THRESHOLD','INVALID')");
                Logger.console(" 4. 'L' List Data");
                Logger.console(" 5. 'Quit' to exit");
                Scanner sc = new Scanner(System.in);
                String[] input = sc.nextLine().split(" ");
                String str = input.length > 1 ? input[1] : "";

                switch (input[0].toUpperCase()) {
                    case Utility.CREDIT -> ClientRequestManager.processCredit();
                    case Utility.READ -> ClientRequestManager.processRead(str);
                    case Utility.VERIFY -> ClientRequestManager.processVerification(str);
                    case Utility.LIST -> ClientRequestManager.processList();
                    case Utility.QUIT -> {
                        if(Blockchain.PROCESS_ID == 0) {
                            Logger.log("Operation now permitted for Process 0...!!!",Blockchain.PROCESS_ID);
                            continue;
                        }
                        Logger.log("De-registering current process from the processing chain and exiting...!!!",Blockchain.PROCESS_ID);
                        ClientRequestManager.deRegisterProcess();
                        System.exit(200);
                    }
                    default -> Logger.log("Please provide valid input...!!!",Blockchain.PROCESS_ID);
                }
            }
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * Broadcasting dummy block when initializing blockchain for the very first time
     */
    public static void broadCastDummyBlock() {
        try {
            Logger.log("Broadcasting dummy block for Blockchain...!!!",Blockchain.PROCESS_ID);
            Block dummyBlock = new Block("This is dummy block for blockchain.");
            dummyBlock.timeStampVerify = String.valueOf(new Date().getTime());
            broadcastVerifiedBlock(dummyBlock);
            Thread.sleep(500);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Send public key to specific Process/Node in the network
     * @param processId
     */
    public static void sendPublicKey(Integer processId) {
        String address = getActiveProcessMap().get(processId);
        Socket socket = SocketHandler.getSocket(address, Ports.getCurrentPort(Ports.PublicKey, processId));
        try {
            if(socket == null) {
                Logger.log(String.format("Public Key server is not up for Process_#%s at %s %s...!!!",processId,address,Ports.getCurrentPort(Ports.PublicKey, processId)),Blockchain.PROCESS_ID);
                return;
            }
            Logger.log(String.format("Sending public key to Process_#%s..!!!",processId),Blockchain.PROCESS_ID);
            SocketHandler.getOutputStream(socket).writeObject(new KeyData(Blockchain.PROCESS_ID, KeyGeneratorUtil.getPublicKey()));
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Notify all active Process/Nodes when any new process joins the network
     * @param processId
     * @throws IOException
     */
    public static void notifyToAll(int processId) throws IOException {
        getActiveProcessMap().entrySet().stream().filter(x -> x.getKey() != processId).forEach(x -> {
            try {
                Thread.sleep(1000);
                Socket socket = SocketHandler.getSocket(x.getValue(), Ports.getCurrentPort(Ports.KeyServer, x.getKey()));
                if(socket == null) {
                    Logger.log(String.format("Key server is not up for Process_#%s at %s %s...!!!",x.getKey(),x.getValue(),Ports.getCurrentPort(Ports.KeyServer, x.getKey())),Blockchain.PROCESS_ID);
                } else {
                    SocketHandler.writeAsJson(socket,JsonHandler.toJson(processId));
                    socket.close();
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Load blockchain from json ledger file
     * @param register
     */
    public static void loadBlockChain(Register register) {
        Blockchain.listBlock = JsonHandler.getGson().fromJson(register.blockChain, new TypeToken<List<Block>>(){}.getType());
        Blockchain.listBlock.forEach(x -> Blockchain.blockChainMap.put(x.uuid,x));
    }
}

/**
 * Key generator util to generate and manage Private and Public keys
 */
class KeyGeneratorUtil {

    public static KeyPairGenerator key;
    public static KeyPair keyPair;
    public static PublicKey pubKey;
    public static PrivateKey priKey;
    public static SecretKey secretKey;

    KeyGeneratorUtil() {
       //generateRSAKey();
    }

    /**
     * Generate and store AES symmetric key
     */
    public static void generateAESKey() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate RSA key pair
     * @param seed
     * @return
     * @throws Exception
     */
    public static KeyPair generateRSAKeyPair(int seed) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        key = KeyPairGenerator.getInstance("RSA");
        key.initialize(seed, random);
        return (key.generateKeyPair());
    }

    /**
     * Generate RSA private and public key
     */
    private static void generateRSAKey(){
        try {
            Logger.log("Generating RSA key pair...!!!", Blockchain.PROCESS_ID);
            keyPair = keyPair == null ? generateRSAKeyPair(2048) : keyPair;
            priKey = keyPair.getPrivate();
            pubKey = keyPair.getPublic();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sign data with private key
     * @param data
     * @param key
     * @return
     */
    public static String signData(String data, PrivateKey key){
        try {
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initSign(key);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verify signed data with public key
     * @param data
     * @param signedData
     * @param key
     * @return
     */
    public static boolean verifySign(String data, String signedData, PublicKey key) {
        try {
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initVerify(key);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(signedData));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate RSA keys or load RSA key from disk if present
     */
    private static void loadRSAKey(){
        Path publicKey = Path.of(String.format("BlockChain_%s.pub",Blockchain.PROCESS_ID));
        Path privateKey = Path.of(String.format("BlockChain_%s.priv",Blockchain.PROCESS_ID));
        if(publicKey.toFile().exists() && privateKey.toFile().exists()){
            try {
                Logger.log("Loading RSA keys from file..!!!",Blockchain.PROCESS_ID);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(new String(Files.readAllBytes(privateKey))));
                X509EncodedKeySpec pubkeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(new String(Files.readAllBytes(publicKey))));
                priKey = keyFactory.generatePrivate(privateKeySpec);
                pubKey = keyFactory.generatePublic(pubkeySpec);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                Logger.log("RSA key files corrupted...!!!",Blockchain.PROCESS_ID);
                generateRSAKey();
                writeRSAKey();
            }
        } else {
            generateRSAKey();
            writeRSAKey();
        }
    }

    /**
     * Write RSA to disk if not already present
     */
    private static void writeRSAKey(){
        try {
            Logger.log("Writing RSA Private key to file...!!!", Blockchain.PROCESS_ID);
            Writer privateOut = new FileWriter(String.format("BlockChain_%s.priv",Blockchain.PROCESS_ID));
            privateOut.write(Base64.getEncoder().encodeToString(priKey.getEncoded()));
            privateOut.close();

            Logger.log("Writing RSA Public key to file...!!!", Blockchain.PROCESS_ID);
            Writer publicOut = new FileWriter(String.format("BlockChain_%s.pub",Blockchain.PROCESS_ID));
            publicOut.write(Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            publicOut.close();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey(){
        if (priKey != null && pubKey != null) return priKey;
        loadRSAKey();
        return priKey;
    }

    public static PublicKey getPublicKey() {
        if (priKey != null && pubKey != null) return pubKey;
        loadRSAKey();
        return pubKey;
    }

    public static SecretKey getSecretKey() {
        if(secretKey != null) return secretKey;
        generateAESKey();
        return secretKey;
    }
}

/**
 * Utility class to manage hash calcualtion
 */
class HashUtility {

    /**
     * Calculate and return hash value of given String data
     * @param data
     * @return
     */
    public static String getHashValue(String data){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data.getBytes(Charset.defaultCharset()));
            byte[] hash = digest.digest();
            return toHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toHexString(byte[] hash) {
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));
        while (hexString.length() < 64) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }
}

/**
 * Handle to manage input text files for Blockchain processing
 */
class InputHandler {
    public static List<String> readInput(String file) throws InterruptedException {
        Path path = Paths.get(file);
            try {
                return Files.readAllLines(path);
            } catch (IOException e) {
                Logger.log("Input file not present. Please provide input file.",Blockchain.PROCESS_ID);
                return new ArrayList<>();
            }
    }
}

/**
 * Json handler to manage GSON requests
 */
class JsonHandler {

    private static Gson gson = new GsonBuilder().setPrettyPrinting().create();

    /**
     * Convert and return Java Object to JSON string type
     * @param obj
     * @return
     */
    public static String toJson(Object obj){
        return gson.toJson(obj);
    }

    /**
     * Return GSON object
     * @return
     */
    public static Gson getGson(){
        return gson;
    }

    /**
     * Write blockchain java list to disk in .json file format
     * @param obj
     * @param name
     */
    public static void writeJson(Object obj, String name){
        FileWriter writer;
        try {
            writer = new FileWriter(name);
            //System.out.println(gson.toJson(obj));
            gson.toJson(obj, writer);
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static FileReader readJson(String fileName){
        try {
            return new FileReader(fileName);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Read blockchain list from json file on the disk
     * @param name
     * @return
     */
    public static List<Block> getBlockList(String name){
        return gson.fromJson(JsonHandler.readJson(name), new TypeToken<List<Block>>(){}.getType());
    }
}

/**
 * Utility class to manage all the ports used in this program
 */
class Ports {

    static int KeyServer = 4500; //Used along with processId
    static int InvalidBlock = 4600; //Used along with processId
    static int PublicKey = 4710; //Used along with processId
    static int UVBlock = 4820; //Used along with processId
    static int Blockchain = 4930; //Used along with processId
    static int TriggerProcess = 5100; //Used along with processId
    static int NodeRegister = 6100; //Standalone server
    static int ActiveNodes = 6200; //Standalone server
    static int ProcessStatus = 6300; //Standalone server

    static int PORT_MULTIPLIER = 1;

    static Integer getCurrentPort(int basePort, int processID){
        return basePort + (processID * PORT_MULTIPLIER);
    }
}

/**
 * Serializable object to share public keys among different process
 */
class KeyData implements Serializable {
    int processId;
    PublicKey publicKey;
    KeyData(int id, PublicKey key){
        processId = id;
        publicKey = key;
    }
}

/**
 * Server to catch public keys shared by all other process in the network
 */
class PublicKeyServer implements Runnable{
    /**
     * Runs this operation.
     */
    @Override
    public void run() {
        ServerSocket keyServer;
        try {
            keyServer = SocketHandler.getServerSocket(Ports.getCurrentPort( Ports.PublicKey, Blockchain.PROCESS_ID));
            Logger.log(String.format("Listening on Public Key server for Process %s at port %s...!!!",Blockchain.PROCESS_ID,keyServer.getLocalPort()),Blockchain.PROCESS_ID);
            while (true){
                Socket socket = keyServer.accept();
                ThreadPool.getService().execute(new PublicKeyWorker(socket));
            }
        } catch (IOException e) {
            if(!Blockchain.EXIT) e.printStackTrace();
        }
    }
}

/**
 * Worker class for PublicKeyServer, catches and stores public key of all the process in the network to be used further for verification
 */
class PublicKeyWorker implements Runnable{
    Socket keySocket;
    static Map<Integer,PublicKey> listKey = new HashMap<>();
    PublicKeyWorker(Socket socket){
        keySocket = socket;
    }

    @Override
    public void run(){
        try {
            KeyData pub = (KeyData) SocketHandler.getInputStream(keySocket).readObject();
            listKey.put(pub.processId, pub.publicKey);
            Logger.log(String.format("Public Key received in Process %s, from Process %s ...!!!",Blockchain.PROCESS_ID,pub.processId),Blockchain.PROCESS_ID);
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}

/**
 * Server to handle case where any new process joins and public key needs to be shared to this new process
 */
class KeyServer implements Runnable {

    @Override
    public void run(){
        Logger.log(String.format("Key server is up and running at port %s...!!!",Ports.getCurrentPort(Ports.KeyServer,Blockchain.PROCESS_ID)),Blockchain.PROCESS_ID);
        ServerSocket serverSocket = SocketHandler.getServerSocket(Ports.getCurrentPort(Ports.KeyServer,Blockchain.PROCESS_ID));
        while (true) {
            try {
                Socket socket = serverSocket.accept();
                ThreadPool.getService().execute(new KeyWorker(socket));
            } catch (IOException e) {
                if(!Blockchain.EXIT) e.printStackTrace();
            }

        }
    }
}

/**
 * Worker class for KeyServer, catches the newly joined process id and share the public key with this process id
 */
class KeyWorker implements Runnable {
    Socket socket;

    KeyWorker(Socket soc){
        socket = soc;
    }

    @Override
    public void run(){
        try {
            String  processId = SocketHandler.readAsJson(socket);
            EventManager.sendPublicKey(Integer.parseInt(processId.trim()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

/**
 * Server to catch Unverified blocks from all the process in the network
 */
class UVBlockServer implements Runnable {

    BlockingQueue<Block> uvQueue;

    UVBlockServer(BlockingQueue<Block> inQueue){
        uvQueue = inQueue;
    }

    @Override
    public void run(){
        ServerSocket uvBlockServer;
        try {
            uvBlockServer = SocketHandler.getServerSocket(Ports.getCurrentPort( Ports.UVBlock, Blockchain.PROCESS_ID));
            Logger.log(String.format("Listening on UVBlock server for Process %s at port %s...!!!",Blockchain.PROCESS_ID,uvBlockServer.getLocalPort()),Blockchain.PROCESS_ID);
            while (true){
                Socket socket = uvBlockServer.accept();
                ThreadPool.getService().execute(new UVBlockWorker(socket, uvQueue));
            }
        } catch (IOException e) {
            if(!Blockchain.EXIT) e.printStackTrace();
        }
    }
}

/**
 * Worker class for UVBlockServer, catches Unverified blocks and store in priority queue for further verification
 */
class UVBlockWorker implements Runnable {

    Socket uvBlockSocket;
    BlockingQueue<Block> uvQueue;

    UVBlockWorker(Socket socket, BlockingQueue<Block> inQueue){
        uvBlockSocket = socket;
        uvQueue = inQueue;
    }

    @Override
    public void run(){
        try {
            String blockString = SocketHandler.readAsJson(uvBlockSocket);
            Block uvBlock = JsonHandler.getGson().fromJson(blockString, Block.class);
            uvQueue.add(uvBlock);
            Logger.log(String.format("UVBlock received from Process %s ...!!!",uvBlock.processId),Blockchain.PROCESS_ID);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

/**
 * Function to verify unverified blocks and broadcast it to blockchain server
 */
class UVBlockVerification implements Runnable {

    BlockingQueue<Block> pbQueue;

    UVBlockVerification(BlockingQueue<Block> inQueue){
        pbQueue = inQueue;
    }

    @Override
    public void run(){
        try {
            Logger.log("Unverified Block Verification process is Up and running...!!!",Blockchain.PROCESS_ID);
                while (true) {
                    Block block = pbQueue.take();
                    while (true){
                        int blocChainSize = Blockchain.listBlock.size();
                        if (!Blockchain.blockChainMap.containsKey(block.uuid)) {
                            if(BCVerificationManager.verifySignedUUID(block) && BCVerificationManager.verifySignedData(block)){
                                for (int i = 0; i < 20; i++) {
                                    if (Blockchain.blockChainMap.containsKey(block.uuid)) break;
                                    block.blockNo = Blockchain.listBlock.size();
                                    Logger.log(String.format("Attempting verification of Block_#%s ...!!!", block.blockNo), Blockchain.PROCESS_ID);
                                    block.verificationProcess = Blockchain.PROCESS_ID;
                                    block.timeStampVerify = String.valueOf(new Date().getTime());
                                    block.previousHash = block.getPreviousHash(Blockchain.listBlock);
                                    block.randomSeed = Utility.randomAlphaNumeric(8);
                                    block.hash = HashUtility.getHashValue(block.getBlockData());
                                    block.signedHash = KeyGeneratorUtil.signData(block.hash, KeyGeneratorUtil.getPrivateKey());
                                    if (BCVerificationManager.verifyThreshold(block)) {  // lower number = more work.
                                        if (Blockchain.blockChainMap.containsKey(block.uuid)) break;
                                        if (blocChainSize != Blockchain.listBlock.size()) continue;
                                        Logger.log(String.format("[(Block#%s from P%s) verified by P%s at time %s]", block.blockNo, block.processId, block.verificationProcess, block.timeStampVerify), Blockchain.PROCESS_ID);
                                        EventManager.broadcastVerifiedBlock(block);
                                        break;
                                    }
                                    Thread.sleep(300);
                                }
                            }
                        } else{
                            break;
                        }
                    }
                }
        } catch (InterruptedException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            if (!(e instanceof InterruptedException)) e.printStackTrace();
        }
    }
}

/**
 * Server to catch verified blocks from all the processes in the network
 */
class BlockchainServer implements Runnable{

    @Override
    public void run(){
        ServerSocket blockServer;
        Socket socket = null;
        try {
            blockServer = SocketHandler.getServerSocket(Ports.getCurrentPort(Ports.Blockchain,Blockchain.PROCESS_ID));
            Logger.log(String.format("Listening on BlockChain server for Process %s at port %s...!!!",Blockchain.PROCESS_ID,blockServer.getLocalPort()),Blockchain.PROCESS_ID);
            while (true){
                socket = blockServer.accept();
                ThreadPool.getService().execute(new BlockchainWorker(socket));
            }
        } catch (IOException e) {
            if(!Blockchain.EXIT) e.printStackTrace();
        }
    }
}

/**
 * Worker class for BlockChainServer, catch verified blocks and form Blockchain
 */
class BlockchainWorker implements Runnable{
    Socket chainSocket;

    BlockchainWorker(Socket socket){
        chainSocket = socket;
    }

    @Override
    public void run(){
        try {
            String blockString = SocketHandler.readAsJson(chainSocket);
            Block vBlock = JsonHandler.getGson().fromJson(blockString, Block.class);
            synchronized (Blockchain.listBlock){
                if(!Blockchain.blockChainMap.containsKey(vBlock.uuid)) {
                    Logger.log(String.format("Verified Block_%s received by Process id %s...!!!",vBlock.blockNo, vBlock.verificationProcess),Blockchain.PROCESS_ID);
                    Blockchain.blockChainMap.put(vBlock.uuid, vBlock);
                    Blockchain.listBlock.add(vBlock);
                    //if (Blockchain.PROCESS_ID == 0) {
                    Logger.log(String.format("Updating Blockchain with verified Block_%s by Process %s...!!!", vBlock.blockNo, vBlock.verificationProcess), Blockchain.PROCESS_ID);
                    JsonHandler.writeJson(new ArrayList<>(Blockchain.listBlock), Utility.LEDGER_FILENAME);
                        //System.out.println(JsonHandler.gson.toJson(new ArrayList<>(Blockchain.listBlock)));
                    //}
                } else {
                    if (Blockchain.blockChainMap.get(vBlock.uuid).timeStampVerify.compareTo(vBlock.timeStampVerify) < 0 ) {
                        Blockchain.blockChainMap.put(vBlock.uuid, vBlock);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

/**
 * Server to listen for the trigger from process invocation thread. (Process 2 in our program)
 */
class TriggerProcessServer implements Runnable {

    BlockingQueue<Block> queue;

    TriggerProcessServer(BlockingQueue<Block> inQueue){
        queue = inQueue;
    }
    @Override
    public void run(){
        ServerSocket serverSocket;
        try {
            serverSocket = SocketHandler.getServerSocket(Ports.getCurrentPort(Ports.TriggerProcess,Blockchain.PROCESS_ID));
            Socket socket = serverSocket.accept();
            ThreadPool.getService().execute(new ProcessWorker(socket, queue));
        } catch (IOException e) {
            if(!Blockchain.EXIT) e.printStackTrace();
        }
    }
}

/**
 * When request received, trigger all the process of blockchain
 */
class ProcessWorker implements Runnable {
    Socket processSocket;
    BlockingQueue<Block> queue;

    ProcessWorker(Socket socket, BlockingQueue<Block> inQueue) {
        processSocket = socket;
        queue = inQueue;
    }

    @Override
    public void run(){
        if(!Blockchain.PROCESS_STARTED){
            Logger.log("Initializing Block Chain processes...!!!", Blockchain.PROCESS_ID);
            Blockchain.PROCESS_STARTED = true;
            EventManager.broadcastKeys();
            EventManager.loadUVBlock(Utility.INPUT_FILENAME);
        }
    }
}

/**
 * Server to manage scenario when an invalid block discovered during blockchain verification
 */
class InvalidBlockServer implements Runnable {

    ServerSocket serverSocket;

    @Override
    public void run(){
        try {
            serverSocket = SocketHandler.getServerSocket(Ports.getCurrentPort(Ports.InvalidBlock,Blockchain.PROCESS_ID));
            while (true){
                Socket socket = serverSocket.accept();
                ThreadPool.getService().execute(new InvalidBlockWorker(socket));
            }
        } catch (IOException e) {
            if(!Blockchain.EXIT) e.printStackTrace();
        }
    }
}

/**
 * Worker class for InvalidBlockServer, broadcast invalid block and all consecutive blocks as unverified for re-verification
 */
class InvalidBlockWorker implements Runnable {
    Socket invalidSocket;

    InvalidBlockWorker(Socket socket){
        invalidSocket = socket;
    }

    @Override
    public void run(){
        try {
            String blockString = SocketHandler.readAsJson(invalidSocket);
            Block block = JsonHandler.getGson().fromJson(blockString, Block.class);
            List<Block> tempList = new ArrayList<>();

            Blockchain.listBlock.stream().filter(x -> x.blockNo >= block.blockNo).forEach(tempList::add);
            Blockchain.listBlock.removeAll(tempList);
            Blockchain.blockChainMap.values().removeIf(x -> (x.blockNo >= block.blockNo));
            tempList.forEach(EventManager::broadcastUVBlock);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}

/**
 * Class to process adhoc client requests
 */
class ClientRequestManager{

    /**
     * Function to process the CREDIT request from the client
     */
    public static void processCredit() {
        List<Block> blockChain = JsonHandler.getBlockList(Utility.LEDGER_FILENAME);
        Map<Integer, List<Integer>> creditMap = new HashMap<>();
        blockChain.stream().filter( block -> block.blockNo > 0).forEach( block -> {
            if(creditMap.containsKey(block.verificationProcess)){
                List<Integer> list = new ArrayList<>(creditMap.get(block.verificationProcess));
                list.add(block.blockNo);
                creditMap.put(block.verificationProcess, list);
            } else{
                creditMap.put(block.verificationProcess, Arrays.asList(block.blockNo));
            }
        });
        creditMap.forEach((key, value) -> Logger.console(String.format("Process_P%s has verified %s Blocks. : %s", key, value.size(), value)));
    }

    /**
     * Function to process READ request from the client
     * @param str
     */
    public static void processRead(String str) {
        EventManager.loadUVBlock(str);
    }

    /**
     * Function to process LIST request from client
     */
    public static void processList() {
        List<Block> newList = new ArrayList<>(Blockchain.listBlock);
        Collections.reverse(newList);
        newList.forEach(block -> Logger.log(String.format("Block_#%s %s ...!!!",block.blockNo, block.data), Blockchain.PROCESS_ID));
    }

    /**
     * Function to process blockchain verification requests from clinet
     * @param val
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public static void processVerification(String val) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        List<Block> blockChain = JsonHandler.getBlockList(Utility.LEDGER_FILENAME);
        switch (val.toUpperCase()) {
            case "HASH" -> BCVerificationManager.verifyHashList(blockChain);
            case "SIGNEDUUID" -> BCVerificationManager.verifySignedUUIDList(blockChain);
            case "SIGNEDDATA" -> BCVerificationManager.verifySignedDataList(blockChain);
            case "SIGNEDHASH" -> BCVerificationManager.verifySignedHashList(blockChain);
            case "THRESHOLD" -> BCVerificationManager.verifyThresholdChain(blockChain);
            case "INVALID" -> BCVerificationManager.fakeInvalidBlock(blockChain);
            default -> BCVerificationManager.verifyAll(blockChain);
        }
    }

    /**
     * Send request for de-registration to the server
     */
    public static void deRegisterProcess(){
            EventManager.registerProcess(false);
        }

    /**
     * When triggered, all active servers will be closed
     */
    public static void closeAllActiveProcess(){
            Blockchain.EXIT = true;
            SocketHandler.closeAllServers();
            ThreadPool.closeService();
        }
}

/**
 * Class to manage all the verification activities related to Blockchain
 */
class BCVerificationManager {

    public static boolean verifyAll(List<Block> blockChain) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return verifyHashList(blockChain) && verifySignedUUIDList(blockChain) && verifyThresholdChain(blockChain) && verifySignedHashList(blockChain) && verifySignedDataList(blockChain);
    }

    /**
     * Function to verify Signed Data of all the blocks in blockchain
     * @param blockChain
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public static boolean verifySignedDataList(List<Block> blockChain) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        boolean result = true;
        int count=0;
        for(int i = 1; i<blockChain.size(); i++) {
            result = verifySignedData(blockChain.get(i));
            count=i;
            if (!result) {
                EventManager.resetBlockChain(blockChain.get(i));
                count--;
                break;
            }
        }
        Logger.log(String.format("Block 1-%s verified successfully for Signed Data...!!!",count),Blockchain.PROCESS_ID);
        if(blockChain.size()-1 - count > 0) {
            Logger.log(String.format("Block_#%s is invalid. Signed Data is not correct...!!!",count+1),Blockchain.PROCESS_ID);
            Logger.log(String.format("Block #%s - #%s follow invalid block...!!!",count+2,blockChain.size()-1),Blockchain.PROCESS_ID);
        }
        return result;
    }

    /**
     * Function to verify all Signed Hash of all the blocks in blockchain
     * @param blockChain
     * @return
     */
    public static boolean verifySignedHashList(List<Block> blockChain) {
        boolean result = true;
        int count=0;
        for(int i = 1; i<blockChain.size(); i++) {
            result = verifySignedHash(blockChain.get(i));
            count=i;
            if (!result) {
                EventManager.resetBlockChain(blockChain.get(i));
                count--;
                break;
            }
        }
        Logger.log(String.format("Block 1-%s verified successfully for Signed Hash...!!!",count),Blockchain.PROCESS_ID);
        if(blockChain.size()-1 - count > 0) {
            Logger.log(String.format("Block_#%s is invalid. Signed hash is not correct...!!!",count+1),Blockchain.PROCESS_ID);
            Logger.log(String.format("Block #%s - #%s follow invalid block...!!!",count+2,blockChain.size()-1),Blockchain.PROCESS_ID);
        }
        return result;
    }

    /**
     * Function to verify Hash of all the blocks in blockchain
     * @param blockChain
     * @return
     */
    public static boolean verifyHashList(List<Block> blockChain) {
        boolean result = true;
        int count = 0;
        for(int i = 1; i<blockChain.size(); i++) {
            result = verifyHashData(blockChain.get(i));
            count = i;
            if (!result) {
                EventManager.resetBlockChain(blockChain.get(i));
                count--;
                break;
            }
        }
        Logger.log(String.format("Block 1-%s verified successfully for HashData...!!!",count),Blockchain.PROCESS_ID);
        if(blockChain.size()-1 - count > 0) {
            Logger.log(String.format("Block_#%s is invalid. Hash data is not correct...!!!",count+1),Blockchain.PROCESS_ID);
            Logger.log(String.format("Block #%s - #%s follow invalid block...!!!",count+2,blockChain.size()-1),Blockchain.PROCESS_ID);
        }
        return result;
    }

    /**
     * Functino to verify Hash Data of given block
     * @param block
     * @return
     */
    public static boolean verifyHashData(Block block){
        boolean result = block.hash.equalsIgnoreCase(HashUtility.getHashValue(block.getBlockData()));
        //String msg = result ? String.format("Hash Data verified for Block_#%s...!!!",block.blockNo) : String.format("Error while processing hash verification for Block_#%s...!!!", block.blockNo);
        //Logger.log(msg, Blockchain.PROCESS_ID);
        return result;
    }


    /**
     * Function to verify Signed UUID of all the blocks in blockchain
     * @param blockChain
     * @return
     */
    public static boolean verifySignedUUIDList(List<Block> blockChain) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        boolean result = true;
        int count= 0;
        for(int i = 1; i<blockChain.size(); i++) {
            result = verifySignedUUID(blockChain.get(i));
            count=i;
            if (!result) {
                EventManager.resetBlockChain(blockChain.get(i));
                count-- ;
                break;
            }
        }
        Logger.log(String.format("Block 1-%s verified successfully for Signed UUID...!!!",count),Blockchain.PROCESS_ID);
        if(blockChain.size() - 1 - count > 0) {
            Logger.log(String.format("Block_#%s is invalid. Signed UUID is not correct...!!!",count+1),Blockchain.PROCESS_ID);
            Logger.log(String.format("Block #%s - #%s follow invalid block...!!!",count+2,blockChain.size()-1),Blockchain.PROCESS_ID);
        }
        return result;
    }

    /**
     * Function to verify Signed UUID of the given block
     * @param block
     * @return
     */
    public static boolean verifySignedUUID(Block block) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        return KeyGeneratorUtil.verifySign(block.uuid.toString(), block.signedUUID, PublicKeyWorker.listKey.get(block.processId));
    }

    /**
     * Function to verify Signed Data of the given block
     * @param block
     * @return
     */
    public static boolean verifySignedData(Block block) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        return KeyGeneratorUtil.verifySign(block.data, block.signedData, PublicKeyWorker.listKey.get(block.processId));
    }

    /**
     * Function to verify Signed Hash of the given block
     * @param block
     * @return
     */
    public static boolean verifySignedHash(Block block) {
        return KeyGeneratorUtil.verifySign(block.hash, block.signedHash, PublicKeyWorker.listKey.get(block.verificationProcess));
    }

    /**
     * Function to verify threshold value of all the blocks in the blockchain
     * @param blockChain
     * @return
     */
    public static boolean verifyThresholdChain(List<Block> blockChain){
        boolean result = true;
        int count = 0;
        for(int i = 1; i<blockChain.size(); i++) {
            result = verifyThreshold(blockChain.get(i));
            count = i;
            if (!result) break;
        }
        Logger.log(String.format("Block 1-%s verified successfully for Threshold...!!!",count),Blockchain.PROCESS_ID);
        if(blockChain.size()-1 - count > 0) {
            Logger.log(String.format("Block_#%s is invalid. Hash data does not solve the threshold...!!!",count),Blockchain.PROCESS_ID);
            Logger.log(String.format("Block #%s - #%s follow invalid block...!!!",count+1,blockChain.size()),Blockchain.PROCESS_ID);
        }
        return result;
    }

    /**
     * Function to verify Threshold value of given block
     * @param block
     * @return
     */
    public static boolean verifyThreshold(Block block) {
        int workNumber = Integer.parseInt(block.hash.substring(0, 4), 16);
        return workNumber < Utility.PUZZLE_THREASHOLD;
    }

    /**
     * Function to demonstrate invalid Block processing by faking a block as invalid and notifying all the other Process/Nodes in the network
     * @param blockChain
     */
    public static void fakeInvalidBlock(List<Block> blockChain){
        int random = ThreadLocalRandom.current().nextInt(1, blockChain.size());
        Logger.log(String.format("Block 1-%s verified successfully...!!!", random-1),Blockchain.PROCESS_ID);
        Logger.log(String.format("Block_#%s is invalid. Verification failed for this block...!!!",random),Blockchain.PROCESS_ID);
        Logger.log(String.format("Block #%s - #%s follow invalid block...!!!", random+1, blockChain.size()),Blockchain.PROCESS_ID);
        EventManager.resetBlockChain(blockChain.get(random));
    }
}


/**
 * Centralized Handler class to manage all the socket operations in JokeServer program
 */
class SocketHandler {

    static List<ServerSocket> listServers = new ArrayList<>();

    /**
     * Create and return instance of ServerSocket on requested port
     * @param port
     * @return
     */
    static ServerSocket getServerSocket(int port) {
        try {
            ServerSocket serverSocket =  new ServerSocket(port);
            listServers.add(serverSocket);
            return serverSocket;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Close all the ServerSocket instances when triggered
     */
    static void closeAllServers() {
        listServers.forEach(x-> {
            try {
                x.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Return a new socket instance for provided set of server/IPAddress and port
     * @param servername
     * @param port
     * @return
     * @throws IOException
     * @throws InterruptedException
     */
    static Socket getSocket(String servername, Integer port) {

            try{
                return new Socket(servername, port);
            }catch (ConnectException e) {
//                System.out.println("Server is not up. Trying to re-connect... !!!");
//                try {
//                    Thread.sleep(1000);
//                } catch (InterruptedException ex) {
//                    throw new RuntimeException(ex);
//                }
                return null;
            } catch (IOException e){
                e.printStackTrace();
            }
        return null;
    }

    /**
     * Return an input stream object with reference to the given socket
     * @param socket
     * @return
     * @throws IOException
     */
    static ObjectInputStream getInputStream(Socket socket) throws IOException {
        //Used for writing or sending object streams to a destination
        InputStream inputStream = socket.getInputStream();
        //It provides the implementations of the functions present in input stream
        //Used for writing primitive data of objects to an output stream
        return new ObjectInputStream(inputStream);
    }

    /**
     * Return an output stream object with reference to the given socket
     * @param socket
     * @return
     * @throws IOException
     */
    static ObjectOutputStream getOutputStream(Socket socket) throws IOException {

        //Used for writing or sending object streams to a destination
        OutputStream outputStream = socket.getOutputStream();
        //It provides the implementations of the functions present in output stream
        //Used for writing primitive data of objects to an output stream
        return new ObjectOutputStream(outputStream);
    }

    /**
     * Return InputStream reference on given socket
     * @param socket
     * @return
     * @throws IOException
     */
    private static InputStream getBufferedStream(Socket socket) throws IOException {
        return new BufferedInputStream(socket.getInputStream());
    }

    /**
     * Return PrintStream reference on given socket
     * @param socket
     * @return
     * @throws IOException
     */
    private static PrintStream getOutputWriter(Socket socket) throws IOException {
        return new PrintStream(socket.getOutputStream());
    }

    /**
     * Funciton to send Json data over socket connection
     * @param socket
     * @param jsonData
     * @throws IOException
     */
    static void writeAsJson(Socket socket, String jsonData) throws IOException {
        PrintStream pr = getOutputWriter(socket);
        pr.println(jsonData);
        pr.flush();
    }

    /**
     * Function to read JSON data over socket connection
     * @param socket
     * @return
     * @throws IOException
     */
    static String readAsJson(Socket socket) throws IOException {
        byte[] byteData = SocketHandler.getBufferedStream(socket).readAllBytes();
        return new String(byteData);
    }
}

/**
 * Utiliy class to manage constants used in this program
 */
class Utility{

    public static final String LOCALHOST = "localhost";
    public static final int PROCESS_COUNT = 3;
    public static final int ZERO = 0;
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    public static final String INPUT_FILENAME = String.format("BlockInput%s.txt", Blockchain.PROCESS_ID);
    public static final String LEDGER_FILENAME = String.format("BlockChainLedger_%s.json",Blockchain.PROCESS_ID);

    public static final String LEDGER_FILENAME_0 = "BlockChainLedger_0.json";
    public static final String CREDIT = "C";
    public static final String READ = "R";
    public static final String VERIFY = "V";
    public static final String LIST = "L";

    public static final String QUIT = "QUIT";

    public static final Integer PUZZLE_THREASHOLD = 10000;

    /**
     * Return a random alpha numeric String when triggered
     * @param count
     * @return
     */
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    /**
     * Return the IPAddress of Master Node/Process i.e. (Process 0)
     * @return
     */
    public static String getMasterAddress() {
        return !Blockchain.masterProcessAddress.isEmpty() ? Blockchain.masterProcessAddress : LOCALHOST;
    }
}

/**
 * Custom Logger class to manage all the console logs in Joke Server program
 */
class Logger{

    /**
     * Input data will be logged on console and a log file will be created for the given domain
     * @param data Any log message
     * @param processId current process id
     */
    static void log(String data, int processId){

        System.out.println(data);

        String domainName = String.format("BlockChain_Log_%s.txt",processId);
        Path path = Paths.get(domainName);
        createLogFile(path,data+"\n");

        domainName = "BlockChain_Log.txt";
        path = Paths.get(domainName);
        createLogFile(path,data+"\n");

    }

    /**
     * Input message will be logged on console
     * @param data
     */
    static void console(String data){
        System.out.println(data);
    }

    /**
     * Create a log file and write the given message to it
     * @param path
     * @param content
     * @throws IOException
     */
    private static void createLogFile(Path path, String content) {
        try {
            Files.writeString(path, content,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}

/**
 * Class to manage all the threads used in Blockchain processing
 */
class ThreadPool {
    private static ExecutorService service = Executors.newCachedThreadPool();

    static ExecutorService getService() {
        service = !service.isShutdown() ? service : Executors.newCachedThreadPool();
        return service;
    }

    static void closeService(){
        service.shutdownNow();
    }
}


/**
 * Handler class to manage encryption and decryption using RSA and AES keys
 */
class CipherHandler {

    static Cipher cipherRSA;
    static Cipher cipherAES;

    static {
        try {
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherAES = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encryptRSA(byte[] data, PrivateKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipherRSA.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipherRSA.doFinal(data));
    }

    public static String decryptRSA(String data, PublicKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipherRSA.init(Cipher.DECRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipherRSA.doFinal(Base64.getDecoder().decode(data)));
    }

    public static String encryptAES(String data, SecretKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipherAES.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipherAES.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decryptAES(String data, SecretKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        cipherAES.init(Cipher.DECRYPT_MODE, key);
        return new String(cipherAES.doFinal(Base64.getDecoder().decode(data)), StandardCharsets.UTF_8);
    }

    public static SecretKey getSecretAESKey(String secret, PublicKey pubkey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return getSecretKeyFromString(decryptRSA(secret, pubkey));
    }

    public static SecretKey getSecretKeyFromString(String key) {
        byte[] bytes = Base64.getDecoder().decode(key);
        return new SecretKeySpec(bytes, 0, bytes.length, "AES");
    }
}

/**
 * Serializable Object to handle Registration and De-registration feature
 */
class Register implements Serializable{
    boolean isRegister;
    int processId;
    boolean isProcessRunning = false;
    String blockChain;
    String responseMessage;

    Register(boolean register){
        isRegister = register;
        processId = Blockchain.PROCESS_ID;
    }
}

/**
 * Server to register and de-register Nodes/Process
 */
class NodeRegisterServer implements Runnable{

    @Override
    public void run(){
        try {
            ServerSocket server = SocketHandler.getServerSocket(Ports.NodeRegister);
            Logger.log(String.format("Node Registration server is up and running at port %s...!!!",Ports.NodeRegister),Blockchain.PROCESS_ID);
            while (true){
                Socket socket = server.accept();
                ThreadPool.getService().execute(new NodeRegisterWorker(socket));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


/**
 * Wroker class for NodeRegisterServer,process the request from any Process/Node for registration and de-registraiton
 */
class NodeRegisterWorker implements Runnable{
    Socket socket;

    NodeRegisterWorker(Socket soc){
        socket = soc;
    }

    @Override
    public void run(){
        try {
            Register record = (Register) SocketHandler.getInputStream(socket).readObject();
            String address = socket.getInetAddress().getHostAddress();
            address = address.equals("localhost") || address.equals("127.0.0.1") ? InetAddress.getLocalHost().getHostAddress() : address;
            Logger.log(String.format("Registration request received by Process id %s running at %s...!!!",record.processId,socket),Blockchain.PROCESS_ID);
            if(record.isRegister){
                if(!Blockchain.mapActiveProcess.containsKey(record.processId)) {
                    Blockchain.mapActiveProcess.put(record.processId, address);
                    record.isProcessRunning = Blockchain.PROCESS_STARTED;
                    record.blockChain = JsonHandler.toJson(Blockchain.listBlock);
                    record.responseMessage = "Registration successful...!!!";
                } else {
                    record.isRegister = false;
                    record.responseMessage = "Registration failed. Another process is already register with same ID...!!!";
                }
                Logger.log(record.responseMessage, Blockchain.PROCESS_ID);
            } else{
                if(Blockchain.mapActiveProcess.containsKey(record.processId)) Blockchain.mapActiveProcess.remove(record.processId);
                else Logger.log("No Active process with this ID...!!!",Blockchain.PROCESS_ID);
            }
            SocketHandler.getOutputStream(socket).writeObject(record);
            if(Blockchain.PROCESS_STARTED && record.isRegister) EventManager.notifyToAll(record.processId);
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}

/**
 * Server to manage request from any process/nodes who wants to know the details of current active processes
 */
class ActiveNodeServer implements Runnable {

    @Override
    public void run (){
        try {
            Logger.log(String.format("Active Node Server is up and running at port %s...!!!",Ports.ActiveNodes),Blockchain.PROCESS_ID);
            ServerSocket serverSocket = SocketHandler.getServerSocket(Ports.ActiveNodes);
            while (true){
                Socket socket = serverSocket.accept();
                ThreadPool.getService().execute(new ActiveNodeWorker(socket));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

/**
 * Wroker class for ActiveNodeServer, process requests and return the details of active nodes/process in the network
 */
class ActiveNodeWorker implements Runnable {
    Socket socket;

    ActiveNodeWorker(Socket soc){
        socket = soc;
    }

    @Override
    public void run(){
        try {
            SocketHandler.writeAsJson(socket,JsonHandler.toJson(Blockchain.mapActiveProcess));
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}


/**
 * Server to listen for requests from any node/process to check the current status of blockchain process
 */
class ProcessStatusServer implements Runnable{

    @Override
    public void run(){
        Logger.log(String.format("Process Status server is up and running at port %s...!!!",Ports.ProcessStatus),Blockchain.PROCESS_ID);
        ServerSocket serverSocket = SocketHandler.getServerSocket(Ports.ProcessStatus);
        while (true) {
            try {
                Socket socket = serverSocket.accept();
                ThreadPool.getService().execute(new ProcessStatusWorker(socket));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}

/**
 * Worker class for ProcessStatusServer, process the request and return the current status of blockchain process
 */
class ProcessStatusWorker implements Runnable {
    Socket socket;

    ProcessStatusWorker(Socket soc){
        socket = soc;
    }

    @Override
    public void run(){
        try {
            SocketHandler.writeAsJson(socket, JsonHandler.toJson(Blockchain.PROCESS_STARTED ? 1 : 0));
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}