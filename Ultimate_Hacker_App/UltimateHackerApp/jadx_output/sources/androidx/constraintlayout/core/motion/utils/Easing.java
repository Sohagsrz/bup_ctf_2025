package androidx.constraintlayout.core.motion.utils;

/* loaded from: classes.dex */
public class Easing {
    private static final String ACCELERATE = "cubic(0.4, 0.05, 0.8, 0.7)";
    private static final String ANTICIPATE = "cubic(0.36, 0, 0.66, -0.56)";
    private static final String ANTICIPATE_NAME = "anticipate";
    private static final String DECELERATE = "cubic(0.0, 0.0, 0.2, 0.95)";
    private static final String LINEAR = "cubic(1, 1, 0, 0)";
    private static final String OVERSHOOT = "cubic(0.34, 1.56, 0.64, 1)";
    private static final String OVERSHOOT_NAME = "overshoot";
    private static final String STANDARD = "cubic(0.4, 0.0, 0.2, 1)";
    String mStr = "identity";
    static Easing sDefault = new Easing();
    private static final String STANDARD_NAME = "standard";
    private static final String ACCELERATE_NAME = "accelerate";
    private static final String DECELERATE_NAME = "decelerate";
    private static final String LINEAR_NAME = "linear";
    public static String[] NAMED_EASING = {STANDARD_NAME, ACCELERATE_NAME, DECELERATE_NAME, LINEAR_NAME};

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0074  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.constraintlayout.core.motion.utils.Easing getInterpolator(java.lang.String r3) {
        /*
            if (r3 != 0) goto L4
            r0 = 0
            return r0
        L4:
            java.lang.String r0 = "cubic"
            boolean r0 = r3.startsWith(r0)
            if (r0 == 0) goto L12
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            r0.<init>(r3)
            return r0
        L12:
            java.lang.String r0 = "spline"
            boolean r0 = r3.startsWith(r0)
            if (r0 == 0) goto L21
            androidx.constraintlayout.core.motion.utils.StepCurve r0 = new androidx.constraintlayout.core.motion.utils.StepCurve
            r0.<init>(r3)
            return r0
        L21:
            java.lang.String r0 = "Schlick"
            boolean r0 = r3.startsWith(r0)
            if (r0 == 0) goto L2f
            androidx.constraintlayout.core.motion.utils.Schlick r0 = new androidx.constraintlayout.core.motion.utils.Schlick
            r0.<init>(r3)
            return r0
        L2f:
            int r0 = r3.hashCode()
            switch(r0) {
                case -1354466595: goto L6a;
                case -1263948740: goto L60;
                case -1197605014: goto L56;
                case -1102672091: goto L4c;
                case -749065269: goto L42;
                case 1312628413: goto L37;
                default: goto L36;
            }
        L36:
            goto L74
        L37:
            java.lang.String r0 = "standard"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L36
            r0 = 0
            goto L75
        L42:
            java.lang.String r0 = "overshoot"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L36
            r0 = 5
            goto L75
        L4c:
            java.lang.String r0 = "linear"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L36
            r0 = 3
            goto L75
        L56:
            java.lang.String r0 = "anticipate"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L36
            r0 = 4
            goto L75
        L60:
            java.lang.String r0 = "decelerate"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L36
            r0 = 2
            goto L75
        L6a:
            java.lang.String r0 = "accelerate"
            boolean r0 = r3.equals(r0)
            if (r0 == 0) goto L36
            r0 = 1
            goto L75
        L74:
            r0 = -1
        L75:
            switch(r0) {
                case 0: goto Lc2;
                case 1: goto Lba;
                case 2: goto Lb2;
                case 3: goto Laa;
                case 4: goto La2;
                case 5: goto L9a;
                default: goto L78;
            }
        L78:
            java.io.PrintStream r0 = java.lang.System.err
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "transitionEasing syntax error syntax:transitionEasing=\"cubic(1.0,0.5,0.0,0.6)\" or "
            java.lang.StringBuilder r1 = r1.append(r2)
            java.lang.String[] r2 = androidx.constraintlayout.core.motion.utils.Easing.NAMED_EASING
            java.lang.String r2 = java.util.Arrays.toString(r2)
            java.lang.StringBuilder r1 = r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.println(r1)
            androidx.constraintlayout.core.motion.utils.Easing r0 = androidx.constraintlayout.core.motion.utils.Easing.sDefault
            return r0
        L9a:
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            java.lang.String r1 = "cubic(0.34, 1.56, 0.64, 1)"
            r0.<init>(r1)
            return r0
        La2:
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            java.lang.String r1 = "cubic(0.36, 0, 0.66, -0.56)"
            r0.<init>(r1)
            return r0
        Laa:
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            java.lang.String r1 = "cubic(1, 1, 0, 0)"
            r0.<init>(r1)
            return r0
        Lb2:
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            java.lang.String r1 = "cubic(0.0, 0.0, 0.2, 0.95)"
            r0.<init>(r1)
            return r0
        Lba:
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            java.lang.String r1 = "cubic(0.4, 0.05, 0.8, 0.7)"
            r0.<init>(r1)
            return r0
        Lc2:
            androidx.constraintlayout.core.motion.utils.Easing$CubicEasing r0 = new androidx.constraintlayout.core.motion.utils.Easing$CubicEasing
            java.lang.String r1 = "cubic(0.4, 0.0, 0.2, 1)"
            r0.<init>(r1)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.Easing.getInterpolator(java.lang.String):androidx.constraintlayout.core.motion.utils.Easing");
    }

    public double get(double x) {
        return x;
    }

    public String toString() {
        return this.mStr;
    }

    public double getDiff(double x) {
        return 1.0d;
    }

    static class CubicEasing extends Easing {
        double mX1;
        double mX2;
        double mY1;
        double mY2;
        private static double sError = 0.01d;
        private static double sDError = 1.0E-4d;

        CubicEasing(String configString) {
            this.mStr = configString;
            int start = configString.indexOf(40);
            int off1 = configString.indexOf(44, start);
            this.mX1 = Double.parseDouble(configString.substring(start + 1, off1).trim());
            int off2 = configString.indexOf(44, off1 + 1);
            this.mY1 = Double.parseDouble(configString.substring(off1 + 1, off2).trim());
            int off3 = configString.indexOf(44, off2 + 1);
            this.mX2 = Double.parseDouble(configString.substring(off2 + 1, off3).trim());
            int end = configString.indexOf(41, off3 + 1);
            this.mY2 = Double.parseDouble(configString.substring(off3 + 1, end).trim());
        }

        CubicEasing(double x1, double y1, double x2, double y2) {
            setup(x1, y1, x2, y2);
        }

        void setup(double x1, double y1, double x2, double y2) {
            this.mX1 = x1;
            this.mY1 = y1;
            this.mX2 = x2;
            this.mY2 = y2;
        }

        private double getX(double t) {
            double t1 = 1.0d - t;
            double f1 = t1 * 3.0d * t1 * t;
            double f2 = 3.0d * t1 * t * t;
            double f3 = t * t * t;
            return (this.mX1 * f1) + (this.mX2 * f2) + f3;
        }

        private double getY(double t) {
            double t1 = 1.0d - t;
            double f1 = t1 * 3.0d * t1 * t;
            double f2 = 3.0d * t1 * t * t;
            double f3 = t * t * t;
            return (this.mY1 * f1) + (this.mY2 * f2) + f3;
        }

        private double getDiffX(double t) {
            double t1 = 1.0d - t;
            return (t1 * 3.0d * t1 * this.mX1) + (6.0d * t1 * t * (this.mX2 - this.mX1)) + (3.0d * t * t * (1.0d - this.mX2));
        }

        private double getDiffY(double t) {
            double t1 = 1.0d - t;
            return (t1 * 3.0d * t1 * this.mY1) + (6.0d * t1 * t * (this.mY2 - this.mY1)) + (3.0d * t * t * (1.0d - this.mY2));
        }

        @Override // androidx.constraintlayout.core.motion.utils.Easing
        public double getDiff(double x) {
            double t = 0.5d;
            double range = 0.5d;
            while (range > sDError) {
                double tx = getX(t);
                range *= 0.5d;
                if (tx < x) {
                    t += range;
                } else {
                    t -= range;
                }
            }
            double x1 = getX(t - range);
            double x2 = getX(t + range);
            double y1 = getY(t - range);
            double y2 = getY(t + range);
            return (y2 - y1) / (x2 - x1);
        }

        @Override // androidx.constraintlayout.core.motion.utils.Easing
        public double get(double x) {
            if (x <= 0.0d) {
                return 0.0d;
            }
            if (x >= 1.0d) {
                return 1.0d;
            }
            double t = 0.5d;
            double range = 0.5d;
            while (range > sError) {
                double tx = getX(t);
                range *= 0.5d;
                if (tx < x) {
                    t += range;
                } else {
                    t -= range;
                }
            }
            double x1 = getX(t - range);
            double x2 = getX(t + range);
            double y1 = getY(t - range);
            double y2 = getY(t + range);
            return (((y2 - y1) * (x - x1)) / (x2 - x1)) + y1;
        }
    }
}
