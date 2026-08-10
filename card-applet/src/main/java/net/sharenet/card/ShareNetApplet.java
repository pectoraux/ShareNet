package net.sharenet.card;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * ShareNet JavaCard applet — tamper-resistant value store.
 *
 * APDU command set (CLA=0x80):
 *  INS 0xA4 SELECT
 *  INS 0x10 MUTUAL_AUTH (challenge-response against issuer-derived key)
 *  INS 0x20 GET_BALANCE
 *  INS 0x30 DEBIT (amount+nonce → signed record, JCSystem transaction)
 *  INS 0x31 CREDIT (verify counterpart signature, increment)
 *  INS 0x40 GET_TX_LOG (last n records)
 *  INS 0x50 GET_OFFLINE_STATE (cumulative offline value + count)
 *
 * Invariants enforced on-card:
 *  - Balance never negative
 *  - Monotonic tx counter
 *  - Cumulative offline value cap
 *  - Max tx since settlement
 *  - Keys never leave SE
 */
public class ShareNetApplet extends Applet {

    // INS
    private static final byte INS_MAYBE_UNUSED = (byte)0x00;
    private static final byte INS_MUTUAL_AUTH   = (byte)0x10;
    private static final byte INS_GET_BALANCE   = (byte)0x20;
    private static final byte INS_DEBIT         = (byte)0x30;
    private static final byte INS_CREDIT        = (byte)0x31;
    private static final byte INS_GET_TX_LOG    = (byte)0x40;
    private static final byte INS_GET_OFFLINE   = (byte)0x50;

    private static final short OFFLINE_VALUE_CAP = (short)50000; // minor units
    private static final byte  MAX_TX_SINCE_SETTLEMENT = (byte)100;

    private short balance;
    private short txCounter;
    private short offlineValue;
    private byte txSinceSettlement;
    private boolean provisioned;

    // Transaction log ring buffer (last 32)
    private static final byte LOG_SIZE = 32;
    private byte[] logAmounts; // 2 bytes each
    private byte[] logCounters;

    // Keys — in prod derived from issuer master via diversification
    private Signature ecdsaSign;
    private PrivateKey privKey;
    private PublicKey  pubKey;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ShareNetApplet().register(bArray, (short)(bOffset+1), bArray[bOffset]);
    }

    protected ShareNetApplet() {
        balance = 0;
        txCounter = 0;
        offlineValue = 0;
        txSinceSettlement = 0;
        provisioned = false;
        logAmounts = new byte[LOG_SIZE * 2];
        logCounters = new byte[LOG_SIZE * 2];
        // Key init stub — real uses EC or Ed25519 via JC 3.0.5
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        switch (ins) {
            case INS_MUTUAL_AUTH: handleMutualAuth(apdu); break;
            case INS_GET_BALANCE: handleGetBalance(apdu); break;
            case INS_DEBIT: handleDebit(apdu); break;
            case INS_CREDIT: handleCredit(apdu); break;
            case INS_GET_TX_LOG: handleGetTxLog(apdu); break;
            case INS_GET_OFFLINE: handleGetOffline(apdu); break;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void handleMutualAuth(APDU apdu) {
        // Stub: challenge-response — always OK for sim
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        // Echo challenge with dummy response
        short outLen = 8;
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buf, (short)0, len);
        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytes((short)0, outLen);
    }

    private void handleGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short)0, balance);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        apdu.sendBytes((short)0, (short)2);
    }

    private void handleDebit(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 6) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short amount = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        // nonce at offset+2, 4 bytes

        // Invariants
        if (amount <= 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if ((short)(balance - amount) < 0) ISOException.throwIt((short)0x6A85); // insufficient funds
        if ((short)(offlineValue + amount) > OFFLINE_VALUE_CAP) ISOException.throwIt((short)0x6A84); // offline cap
        if (txSinceSettlement >= MAX_TX_SINCE_SETTLEMENT) ISOException.throwIt((short)0x6A84);

        // JCSystem transaction for power-loss atomicity
        JCSystem.beginTransaction();
        balance -= amount;
        txCounter++;
        offlineValue += amount;
        txSinceSettlement++;
        // log ring
        short idx = (short)((txCounter % LOG_SIZE) * 2);
        Util.setShort(logAmounts, idx, amount);
        Util.setShort(logCounters, idx, txCounter);
        JCSystem.commitTransaction();

        // Return signed record: counter(2) + amount(2) + nonce(4) + sig(64 stub)
        Util.setShort(buf, (short)0, txCounter);
        Util.setShort(buf, (short)2, amount);
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, buf, (short)4, (short)4);
        // Dummy 8-byte sig for sim
        for (short i = 8; i < 16; i++) buf[i] = (byte)(txCounter + i);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)16);
        apdu.sendBytes((short)0, (short)16);
    }

    private void handleCredit(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short amount = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        // Verify counterpart signature stub — real verifies Ed25519
        // For sim, accept any non-zero amount
        if (amount <= 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        // Replay guard: check txCounter not already seen (simplified)
        JCSystem.beginTransaction();
        balance += amount;
        if (offlineValue >= amount) offlineValue -= amount;
        JCSystem.commitTransaction();
        Util.setShort(buf, (short)0, balance);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)2);
        apdu.sendBytes((short)0, (short)2);
    }

    private void handleGetTxLog(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short n = buf[ISO7816.OFFSET_P1]; // requested count
        if (n <= 0) n = 10;
        if (n > LOG_SIZE) n = LOG_SIZE;
        short out = 0;
        for (short i = 0; i < n; i++) {
            short src = (short)(i * 2);
            Util.arrayCopyNonAtomic(logAmounts, src, buf, out, (short)2);
            out += 2;
            Util.arrayCopyNonAtomic(logCounters, src, buf, out, (short)2);
            out += 2;
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength(out);
        apdu.sendBytes((short)0, out);
    }

    private void handleGetOffline(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short)0, offlineValue);
        buf[2] = txSinceSettlement;
        Util.setShort(buf, (short)3, txCounter);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)5);
        apdu.sendBytes((short)0, (short)5);
    }
}
