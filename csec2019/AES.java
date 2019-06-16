package csec2019;
public class AES {
    public byte[] ksched;
    public byte[] isched;
    public AES(byte[] key) throws Exception {
        if (key.length % 8 != 0) {
            throw new Exception("Illegal Key Length");
        }
        int Nk = key.length / 4;
        int Nr = 0;
        try {
            Nr = (new int[] {10, 12, 14})[Nk / 2 - 2];
        } catch (IndexOutOfBoundsException e) {
            throw new Exception("Illegal Key Length");
        }
        ksched = new byte[16 * (Nr + 1)];
        isched = new byte[16 * (Nr + 1)]; // May not be necessary
        KeyExpansion(key, ksched);
        InvExpansion(ksched, isched);
    }

    public void add(byte[] r, int roff, byte[] s, int soff, int count) {
        for (int i = 0; i < count; i++) r[roff + i]^= s[soff + i];
    }
    public void xtime(byte[] r, int roff) {
        boolean sub = (r[roff]&0x80) != 0x00;
        r[roff]<<= 1;
        if (sub) r[roff]^= bmod[1];
    }
    public void multb(byte[] r, int roff, byte[] s, int soff) {
        byte sreg = s[soff];
        byte[] intm = new byte[] {r[roff]};
        r[roff] = 0;
        while (sreg != 0) {
            if ((sreg & 0x01) != 0x00) r[roff]^= intm[0];
            xtime(intm, 0);
            sreg>>>= 1;
        }
    }
    public void multw(byte[] r, int roff, byte[] s, int soff) {
        byte p[] = new byte[] {0x00};
        byte t[] = new byte[] {r[roff + 0],
                r[roff + 1],
                r[roff + 2],
                r[roff + 3]};
        for (int i = 0; i < 4; i++) {
            r[roff + i] = 0;
            for (int j = 0; j < 4; j++) {
                p[0] = t[(i - j + 4) % 4];
                multb(p, 0, s, soff + (j % 4));
                r[roff + i]^= p[0];
            }
        }
    }
    public byte[] bmod = new byte[] {0x01, 0x1b};
    public byte[] sbox = new byte[] {
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76,
            (byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0,
            (byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15,
            (byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75,
            (byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84,
            (byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf,
            (byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8,
            (byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2,
            (byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73,
            (byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb,
            (byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79,
            (byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08,
            (byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a,
            (byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e,
            (byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf,
            (byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16
    };
    public byte[] ibox = new byte[] {
            (byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb,
            (byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb,
            (byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e,
            (byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25,
            (byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92,
            (byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84,
            (byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06,
            (byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b,
            (byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73,
            (byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e,
            (byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b,
            (byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4,
            (byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f,
            (byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef,
            (byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61,
            (byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d
    };
    public byte[] fixedp = new byte[] {0x02, 0x01, 0x01, 0x03};
    public byte[] fixedi = new byte[] {0x0e, 0x09, 0x0d, 0x0b};

    public void SubBytes(byte[] state) {
        for (int i = 0; i < state.length; i++) state[i] = sbox[(state[i]+256)%256];
    }
    public void InvSubBytes(byte[] state) {
        for (int i = 0; i < state.length; i++) state[i] = ibox[(state[i]+256)%256];
    }
    public void ShiftRows(byte[] state) {
        byte t;
        t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
        t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
        t = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t;
    }
    public void InvShiftRows(byte[] state) {
        byte t;
        t = state[1]; state[1] = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = t;
        t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
        t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
    }
    public void MixColumns(byte[] state) {
        for (int i = 0; i < state.length; i+= 4) multw(state, i, fixedp, 0);
    }
    public void InvMixColumns(byte[] state) {
        for (int i = 0; i < state.length; i+= 4) multw(state, i, fixedi, 0);
    }
    public void AddRoundKey(byte[] state, byte[] w, int woff) {
        add(state, 0, w, woff, 16);
    } // Is also InvAddRoundKey

    public void Cipher(byte[] in, byte[] out, byte[] w) {
        int Nr = w.length / 16 - 1;
        System.arraycopy(in, 0, out, 0, 16);

        AddRoundKey(out, w, 0);
        for (int i = 0; i < Nr - 1; i++) {
            SubBytes(out);
            ShiftRows(out);
            MixColumns(out);
            AddRoundKey(out, w, 16*(i + 1));
        }
        SubBytes(out);
        ShiftRows(out);
        AddRoundKey(out, w, 16*Nr);
    }
    public void InvCipher(byte[] in, byte[] out, byte[] w) {
        int Nr = w.length / 16 - 1;
        System.arraycopy(in, 0, out, 0, 16);

        AddRoundKey(out, w, 16*Nr);
        for (int i = Nr - 2; i >= 0; i--) {
            InvSubBytes(out);
            InvShiftRows(out);
            InvMixColumns(out);
            AddRoundKey(out, w, 16*(i + 1));
        }
        InvSubBytes(out);
        InvShiftRows(out);
        AddRoundKey(out, w, 0);
    }

    public void SubWord(byte[] w) {
        for (int i = 0; i < 4; i++) w[i] = sbox[(w[i]+256)%256];
    }
    public void RotWord(byte[] w) {
        byte t = w[0]; w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = t;
    }

    public void KeyExpansion(byte[] k, byte[] w) {
        int Nk = k.length / 4;
        int Nr = (new int[] {10, 12, 14})[Nk / 2 - 2];
        byte[] t = new byte[4];
        byte[] Rcon = new byte[] {1, 0, 0, 0};

        System.arraycopy(k, 0, w, 0, k.length);
        for (int i = Nk*4; i < 16*(Nr + 1); i+= 4) {
            System.arraycopy(w, i - 4, t, 0, 4);
            if (i % k.length == 0) {
                RotWord(t);
                SubWord(t);
                t[0]^= Rcon[0];
                xtime(Rcon, 0);
            } else if (Nk > 6 && i % k.length == 16) {
                SubWord(t);
            }
            System.arraycopy(w, i - k.length, w, i, 4);
            add(w, i, t, 0, 4);
        }
    }
    public void InvExpansion(byte[] w, byte[] v) {
        System.arraycopy(w, 16, v, 16, w.length - 32);
        InvMixColumns(v);
        System.arraycopy(w, 0, v, 0, 16);
        System.arraycopy(w, w.length - 16, v, w.length - 16, 16);
    }

    public byte[] encrypt(byte[] in) throws Exception {
        if (in.length != 16) {
            throw new Exception("Illegal Block Size");
        }
        byte[] out = new byte[16];
        Cipher(in, out, ksched);
        return out;
    }
    public byte[] decrypt(byte[] in) throws Exception {
        if (in.length != 16) {
            throw new Exception("Illegal Block Size");
        }
        byte[] out = new byte[16];
        InvCipher(in, out, isched);
        return out;
    }
}