package in.raulmart.cs_dns_parser;

import java.math.BigInteger;

// From Cobalt Strike 4.1
public class RecvConversation {
    protected String id;
    protected String dtype;
    protected long size = -1L;
    protected Packer buffer = new Packer();

    public RecvConversation(String id, String type) {
        this.id = id;
        this.dtype = type;
    }

    public long next(String var1) {
        if (this.size == -1L) {
            try {
                BigInteger var2 = new BigInteger(var1, 16);
                this.size = var2.longValue();
            } catch (Exception var3) {
                this.size = 0L;
                return 0L;
            }
        } else {
            this.buffer.addHex(var1);
        }

        return 0L;
    }

    public boolean isComplete() {
        return this.buffer.size() >= this.size;
    }

    public byte[] result() {
        byte[] var1 = this.buffer.getBytes();
        return var1;
    }

    public String toString() {
        return "[id: " + this.id + ", type: " + this.dtype + ", recv'd: " + this.buffer.size() + ", total: " + this.size + "]";
    }
}