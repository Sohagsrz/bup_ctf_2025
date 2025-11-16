package com.nomanprodhan.ultimatehackerapp;

import androidx.appcompat.app.AppCompatDelegate;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.core.location.LocationRequestCompat;
import androidx.recyclerview.widget.ItemTouchHelper;
import java.nio.charset.StandardCharsets;
import kotlin.UByte;

/* loaded from: classes3.dex */
public class Obfuscator {
    private static final String[] SIGN = {"20gf2zcbq59g20z33qd7g4bz12q7fg75z59q56gb4zf5q89g56zb9q65g08z0cqb9g89z9dq56g65z7dq12g88zfbq7bg1dz70qa4gfbz12q1eg74zd3q4bg00z33qc7g59z08q74gd3z", "84g7az8fq52g84zbbq93g40zb6qacg23z03q3egf7zf7q9cgeaz76qc9g82zd0q70gefz1eq3cg73z33q5dgfez31qefgdfz3cqedgf5zdfqd0g70za7q57ga4zf8qdbgddzc2qf3gcfz17q38g3dz8dq94ga8z3cqb7g16z", "52g43z98qa3g52z82q84gb1z60q95g34zf2qe8gcezccqebg3ez48qeag6ez3eqcegcezafq24g0czdaq6dg3ez0dqe0ge8z3eq48gd6z2bq08gc9zb0qe7g50zc5q8ega7zeeq04g9az65q7eg05za0qe7g", "87g5ez38q65g87z9fq24g77zb5q88g94z34q3dgd3z7aq2agddzd0q40ga8ze9qd3g6cz2dqebg55z4aqa8gebzd3q62ga9zd7qd3g6czeaqddg94z78qaagb9z18q0cg61z3bq19g3aza3qabg18z00q21g", "10gfazfdqd1g10z3bqe1gc3z22qadg43z41qa8g77za9q5eg4az30qbdg1ez66q72ga5z1dq7cgb5z9dq1cg7ez34qa9gd8z52q34g9dz99q5eg7ezefq50g1ez7aq57g50z04qfagc7z51q3eg78z", "bbg84z35qb5gbbz45q29ga7z89q8fg6dz7bqdbg0ez69qbdgd3z09q65gbaze1qcdg65zbaqf1g8dz55qf8gefz8cq4fg3czd5q09g63z7bqedg4az63qbagf1z00q65g79zebq4fg9fz34qafg84z0fq35g95z06q"};
    private static final int[][][] LANES = {new int[][]{new int[]{116, 162, 138, 23}, new int[]{174, 103, 71, 195}, new int[]{177, 206, 232, 103}, new int[]{79, 244, 157, 218}, new int[]{2, 94, TypedValues.TYPE_TARGET, 13}, new int[]{227, 214, 51, 218}, new int[]{73, 193, 84, 255}, new int[]{227, 120, 196, 5}, new int[]{LocationRequestCompat.QUALITY_LOW_POWER, 70, 115, 231}, new int[]{184, 47, 22, 191}}, new int[][]{new int[]{38, 128, 168, 59}, new int[]{211, 113, 251, 48}, new int[]{71, 11, 183, 15}, new int[]{193, 131, LocationRequestCompat.QUALITY_LOW_POWER, 58}, new int[]{12, 39, 170, 94}, new int[]{81, 152, 181, 82}, new int[]{234, 72, 13, 119}, new int[]{63, 63, 163, 147}, new int[]{20, 251, 183, 11}, new int[]{241, 135, 182, 181}}, new int[][]{new int[]{77, 100, 35, 252}, new int[]{8, 137, 218, 208}, new int[]{7, 172, 100, ItemTouchHelper.Callback.DEFAULT_SWIPE_ANIMATION_DURATION}, new int[]{254, 91, 154, 120}, new int[]{117, 37, 30, 39}, new int[]{162, 216, 69, 71}, new int[]{26, 245, 6, 95}, new int[]{9, 169, 23, 41}, new int[]{140, 246, 187, 8}, new int[]{254, 17, 70, 157}}, new int[][]{new int[]{167, 16, 115, 231}, new int[]{223, 253, 195, 174}, new int[]{165, 187, 123, 17}, new int[]{188, 173, 86, 84}, new int[]{198, 70, 25, 209}, new int[]{105, 147, 128, 152}, new int[]{224, 150, 46, 137}, new int[]{236, 209, 184, 178}, new int[]{161, 30, 105, 231}, new int[]{134, 188, 238, 122}}, new int[][]{new int[]{AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR, 130, 145, 53}, new int[]{248, 191, 27, 128}, new int[]{199, 134, 242, 157}, new int[]{139, TypedValues.TYPE_TARGET, 40, 131}, new int[]{201, 130, 244, 140}, new int[]{53, 45, 215, 20}, new int[]{253, 214, 157, 209}, new int[]{8, 175, 214, 217}, new int[]{229, 3, 105, 56}, new int[]{13, 193, 41, 199}}, new int[][]{new int[]{185, 123, 245, 164}, new int[]{229, 244, 51, 231}, new int[]{39, 211, 122, 158}, new int[]{223, 166, 107, 224}, new int[]{57, 143, 126, 0}, new int[]{254, 49, 222, 164}, new int[]{46, 206, 39, 67}, new int[]{95, 132, 219, 175}, new int[]{30, 193, 152, 42}, new int[]{86, 28, 240, 138}}};

    public enum Marker {
        SLOT_A,
        SLOT_B,
        SLOT_C,
        SLOT_D,
        SLOT_E,
        SLOT_F,
        SLOT_NONE
    }

    public static Marker probe(String input) {
        if (input == null) {
            return Marker.SLOT_NONE;
        }
        String src = input.trim();
        if (src.isEmpty()) {
            return Marker.SLOT_NONE;
        }
        for (int idx = 0; idx < SIGN.length; idx++) {
            String expected = SIGN[idx];
            int[][] fam = LANES[idx];
            for (int[] iArr : fam) {
                String encoded = shuffle(src, iArr);
                if (expected.equals(encoded)) {
                    switch (idx) {
                        case 0:
                            return Marker.SLOT_A;
                        case 1:
                            return Marker.SLOT_B;
                        case 2:
                            return Marker.SLOT_C;
                        case 3:
                            return Marker.SLOT_D;
                        case 4:
                            return Marker.SLOT_E;
                        case 5:
                            return Marker.SLOT_F;
                    }
                }
            }
        }
        return Marker.SLOT_NONE;
    }

    public static String mix(String input) {
        if (input == null) {
            input = "";
        }
        return shuffle(input, LANES[0][0]);
    }

    private static String shuffle(String input, int[] lane) {
        int v;
        if (input == null) {
            input = "";
        }
        String s = new StringBuilder("CSPRINT:" + input.trim() + ":ANDROID").reverse().toString();
        StringBuilder stage4 = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= 'a' && ch <= 'z') {
                stage4.append(Character.toUpperCase(ch));
            } else if (ch >= 'A' && ch <= 'Z') {
                stage4.append(Character.toLowerCase(ch));
            } else if (ch >= '0' && ch <= '9') {
                int d = ch - '0';
                stage4.append((char) (((d + 7) % 10) + 48));
            } else {
                stage4.append(ch);
            }
        }
        byte[] data = stage4.toString().getBytes(StandardCharsets.UTF_8);
        byte[] keyed = new byte[data.length];
        for (int i2 = 0; i2 < data.length; i2++) {
            int v2 = data[i2] & UByte.MAX_VALUE;
            int k = lane[i2 % lane.length] & 255;
            keyed[i2] = (byte) (v2 ^ k);
        }
        int i3 = keyed.length;
        byte[] twisted = new byte[i3];
        for (int i4 = 0; i4 < keyed.length; i4++) {
            int v3 = keyed[i4] & UByte.MAX_VALUE;
            if (i4 % 2 == 0) {
                v = ((v3 << 1) & 255) | (v3 >>> 7);
            } else {
                v = ((v3 >>> 2) | ((v3 << 6) & 255)) & 255;
            }
            twisted[i4] = (byte) v;
        }
        StringBuilder out = new StringBuilder(twisted.length * 3);
        for (int i5 = 0; i5 < twisted.length; i5++) {
            int v4 = twisted[i5] & UByte.MAX_VALUE;
            if (v4 < 16) {
                out.append('0');
            }
            out.append(Integer.toHexString(v4));
            int mod = i5 % 3;
            if (mod == 0) {
                out.append('g');
            } else if (mod == 1) {
                out.append('z');
            } else {
                out.append('q');
            }
        }
        return out.toString();
    }
}
