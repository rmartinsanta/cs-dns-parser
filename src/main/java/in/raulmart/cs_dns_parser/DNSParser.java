package in.raulmart.cs_dns_parser;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class DNSParser {
    /**
     * Filename containing all DNS queries sent by the beacon. One query per line.
     */
    public static final String DNS_QUERIES_FILENAME = "queries.txt";

    /**
     * Cobalt strike default IV for AES
     */
    public static final String CS_IV = "abcdefghijklmnop"; //

    public static void main(String[] args) throws Exception {
        if(args.length != 2){
            System.out.println("Usage: java -jar file.jar [AESKey] [HMACKey]");
            System.exit(-1);
        }

        String AESKey = args[0];
        String HMACKey = args[1];

        Map<String, List<ConversationFragment>> conversations = new LinkedHashMap<>();
        Set<String> notImplemented = new HashSet<>();

        // Build conversations map
        try (var br = Files.newBufferedReader(Path.of(DNS_QUERIES_FILENAME))){
            String line;
            while((line = br.readLine()) != null){
                var parts = line.split("\\.");
                switch (parts[0]) {
                    case "post" -> {
                        ConversationFragment data = getData(parts);
                        conversations.putIfAbsent(data.conversationId, new ArrayList<>());
                        conversations.get(data.conversationId).add(data);
                    }
                    default -> notImplemented.add(parts[0]);
                }
            }
        }

        if(!notImplemented.isEmpty()){
            System.out.format("[WARNING] Unknown query types found: %s%n%n", notImplemented);
        }

        for(var e: conversations.entrySet()){
            // Rebuild conversation
            var fragments = e.getValue();
            var firstFragment = fragments.get(0);
            var recv = new RecvConversation(firstFragment.conversationId, firstFragment.type);
            for (var fragment : fragments) {
                recv.next(fragment.payload);
            }

            // If conversation is valid, decrypt and parse
            if(recv.isComplete()) {
                var encrypted = recv.result();
                var decrypted = decrypt(encrypted, AESKey, HMACKey);
                System.out.format(">>>>>>> Id: %s >>>>>> %n", firstFragment.conversationId);
                if(decrypted.length > 0){
                    processCallbackData(decrypted);
                } else {
                    System.out.println("Skipped processing");
                }
                System.out.format("<<<<<<<<<<<<<<<<<<<%n%n");
            } else {
                System.out.println("[WARNING] Invalid conversation: TIME TO DEBUG! (probably missing data)");
            }
        }

    }

    private static void processCallbackData(byte[] decryptedbytes) throws IOException {
        var in = new DataInputStream(new ByteArrayInputStream(decryptedbytes));
        var callbackType = CallbackType.mapping.get(in.readInt());
        System.out.format("Type: %s%n", callbackType.toString());
        switch (callbackType){
            // TODO Implement behaviour for each packet type
            default -> System.out.println("Raw data: " + new String(in.readAllBytes()));
        }
    }

    private static byte[] decrypt(byte[] payload, String AESKey, String HMACKey) throws Exception {
        var ivspec = new IvParameterSpec(CS_IV.getBytes());
        var keyspec = new SecretKeySpec(fromHex(AESKey), "AES");
        var cypher = Cipher.getInstance("AES/CBC/NoPadding");
        cypher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

        byte[] encrypteddata = Arrays.copyOfRange(payload, 0, payload.length - 16);
        byte[] hmac = Arrays.copyOfRange(payload, payload.length - 16, payload.length);
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(fromHex(HMACKey), "HmacSHA256"));
        byte[] calculatedhmac = mac.doFinal(encrypteddata);

        boolean matchesHMAC = isValidHMAC(hmac, calculatedhmac);
        if(!matchesHMAC){
            System.out.println("WARNING: Invalid HMAC, skipping packet");
            return new byte[0];
        }

        byte[] decrypted =  cypher.doFinal(encrypteddata);

        var in = new DataInputStream(new ByteArrayInputStream(decrypted));
        int counter = in.readInt();
        int size = in.readInt();
        if (size >= 0 && size <= decrypted.length) {
            byte[] realdata = new byte[size];
            in.readFully(realdata, 0, size);
            return realdata;
        } else {
            throw new IllegalStateException("Invalid size");
        }
    }

    private static boolean isValidHMAC(byte[] b1, byte[] b2){
        if(b1.length < 16 || b2.length < 16){
            throw new IllegalArgumentException("HMAC data must be at least 16 bytes");
        }
        for (int i = 0; i < 16; i++) { // Only check first 16 bytes
            if(b1[i] != b2[i]){
                return false;
            }
        }
        return true;
    }

    private static byte[] fromHex(String hexString){
        byte[] result = new byte[hexString.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(hexString.substring(index, index + 2), 16);
            result[i] = (byte) j;
        }
        return result;
    }


    public record ConversationFragment(String payload, int packetNumber, String conversationId, String sessionId, String type) {}

    private static ConversationFragment getData(String[] lineParts){
        StringBuilder data = new StringBuilder(lineParts[1].substring(1));
        int nSegments = lineParts[1].charAt(0) - '0';
        for (int i = 1; i < nSegments; i++) {
            data.append(lineParts[1 + i]);
        }
        String conversationPacket = lineParts[1 + nSegments];
        // TODO potential bug --> conversationId may be 7 or 8 hex chars. Manually fixed in queries.txt to 8.
        String conversationId = conversationPacket.substring(conversationPacket.length()-8);
        int nDigits = conversationPacket.length() - conversationId.length();
        int packetNumber = Integer.parseInt(conversationPacket.substring(0, nDigits), 16);
        return new ConversationFragment(data.toString(), packetNumber, conversationId, lineParts[1 + nSegments + 1], lineParts[0]);
    }


    public enum CallbackType {
        // Extracted from https://github.com/DidierStevens/Beta/blob/master/cs-parse-http-traffic.py
        OUTPUT_KEYSTROKES(1),
        DOWNLOAD_START(2),
        OUTPUT_SCREENSHOT(3),
        SOCKS_DIE(4),
        SOCKS_WRITE(5),
        SOCKS_RESUME(6),
        SOCKS_PORTFWD(7),
        DOWNLOAD_WRITE(8),
        DOWNLOAD_COMPLETE(9),
        BEACON_LINK(10),
        DEAD_PIPE(11),
        BEACON_CHECKIN(12),
        BEACON_ERROR(13),
        PIPES_REGISTER(14),
        BEACON_IMPERSONATED(15),
        BEACON_GETUID(16),
        BEACON_OUTPUT_PS(17),
        ERROR_CLOCK_SKEW(18),
        BEACON_GETCWD(19),
        BEACON_OUTPUT_JOBS(20),
        BEACON_OUTPUT_HASHES(21),
        TODO(22),
        SOCKS_ACCEPT(23),
        BEACON_OUTPUT_NET(24),
        BEACON_OUTPUT_PORTSCAN(25),
        BEACON_EXIT(26),
        OUTPUT(30),
        ;

        private final static Map<Integer, CallbackType> mapping;
        private int packetType;
        CallbackType(int packetType) {
            this.packetType = packetType;
        }

        public int getId() {
            return packetType;
        }

        static {
            mapping = new HashMap<>();
            for(var v: CallbackType.values()){
                mapping.put(v.packetType, v);
            }
        }
    }
}
