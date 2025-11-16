package androidx.constraintlayout.core.motion.utils;

import java.util.Arrays;

/* loaded from: classes.dex */
public class Oscillator {
    public static final int BOUNCE = 6;
    public static final int COS_WAVE = 5;
    public static final int CUSTOM = 7;
    public static final int REVERSE_SAW_WAVE = 4;
    public static final int SAW_WAVE = 3;
    public static final int SIN_WAVE = 0;
    public static final int SQUARE_WAVE = 1;
    public static String TAG = "Oscillator";
    public static final int TRIANGLE_WAVE = 2;
    double[] mArea;
    MonotonicCurveFit mCustomCurve;
    String mCustomType;
    int mType;
    float[] mPeriod = new float[0];
    double[] mPosition = new double[0];
    double mPI2 = 6.283185307179586d;
    private boolean mNormalized = false;

    public String toString() {
        return "pos =" + Arrays.toString(this.mPosition) + " period=" + Arrays.toString(this.mPeriod);
    }

    public void setType(int type, String customType) {
        this.mType = type;
        this.mCustomType = customType;
        if (this.mCustomType != null) {
            this.mCustomCurve = MonotonicCurveFit.buildWave(customType);
        }
    }

    public void addPoint(double position, float period) {
        int len = this.mPeriod.length + 1;
        int j = Arrays.binarySearch(this.mPosition, position);
        if (j < 0) {
            j = (-j) - 1;
        }
        this.mPosition = Arrays.copyOf(this.mPosition, len);
        this.mPeriod = Arrays.copyOf(this.mPeriod, len);
        this.mArea = new double[len];
        System.arraycopy(this.mPosition, j, this.mPosition, j + 1, (len - j) - 1);
        this.mPosition[j] = position;
        this.mPeriod[j] = period;
        this.mNormalized = false;
    }

    public void normalize() {
        double totalArea = 0.0d;
        double totalCount = 0.0d;
        for (int i = 0; i < this.mPeriod.length; i++) {
            totalCount += this.mPeriod[i];
        }
        for (int i2 = 1; i2 < this.mPeriod.length; i2++) {
            float h = (this.mPeriod[i2 - 1] + this.mPeriod[i2]) / 2.0f;
            double w = this.mPosition[i2] - this.mPosition[i2 - 1];
            totalArea += h * w;
        }
        for (int i3 = 0; i3 < this.mPeriod.length; i3++) {
            float[] fArr = this.mPeriod;
            fArr[i3] = fArr[i3] * ((float) (totalCount / totalArea));
        }
        this.mArea[0] = 0.0d;
        for (int i4 = 1; i4 < this.mPeriod.length; i4++) {
            float h2 = (this.mPeriod[i4 - 1] + this.mPeriod[i4]) / 2.0f;
            double w2 = this.mPosition[i4] - this.mPosition[i4 - 1];
            this.mArea[i4] = this.mArea[i4 - 1] + (h2 * w2);
        }
        this.mNormalized = true;
    }

    double getP(double time) {
        if (time <= 0.0d) {
            return 0.0d;
        }
        if (time >= 1.0d) {
            return 1.0d;
        }
        int index = Arrays.binarySearch(this.mPosition, time);
        if (index < 0) {
            index = (-index) - 1;
        }
        double m = (this.mPeriod[index] - this.mPeriod[index - 1]) / (this.mPosition[index] - this.mPosition[index - 1]);
        return this.mArea[index - 1] + ((this.mPeriod[index - 1] - (this.mPosition[index - 1] * m)) * (time - this.mPosition[index - 1])) + ((((time * time) - (this.mPosition[index - 1] * this.mPosition[index - 1])) * m) / 2.0d);
    }

    public double getValue(double time, double phase) {
        double angle = getP(time) + phase;
        switch (this.mType) {
            case 1:
                return Math.signum(0.5d - (angle % 1.0d));
            case 2:
                return 1.0d - Math.abs((((angle * 4.0d) + 1.0d) % 4.0d) - 2.0d);
            case 3:
                return (((angle * 2.0d) + 1.0d) % 2.0d) - 1.0d;
            case 4:
                return 1.0d - (((angle * 2.0d) + 1.0d) % 2.0d);
            case 5:
                return Math.cos(this.mPI2 * (phase + angle));
            case 6:
                double x = 1.0d - Math.abs(((angle * 4.0d) % 4.0d) - 2.0d);
                return 1.0d - (x * x);
            case 7:
                return this.mCustomCurve.getPos(angle % 1.0d, 0);
            default:
                return Math.sin(this.mPI2 * angle);
        }
    }

    double getDP(double time) {
        if (time <= 0.0d) {
            return 0.0d;
        }
        if (time >= 1.0d) {
            return 1.0d;
        }
        int index = Arrays.binarySearch(this.mPosition, time);
        if (index < 0) {
            index = (-index) - 1;
        }
        double m = (this.mPeriod[index] - this.mPeriod[index - 1]) / (this.mPosition[index] - this.mPosition[index - 1]);
        return (m * time) + (this.mPeriod[index - 1] - (this.mPosition[index - 1] * m));
    }

    public double getSlope(double time, double phase, double dphase) {
        double angle = phase + getP(time);
        double dangle_dtime = getDP(time) + dphase;
        switch (this.mType) {
            case 1:
                return 0.0d;
            case 2:
                return dangle_dtime * 4.0d * Math.signum((((angle * 4.0d) + 3.0d) % 4.0d) - 2.0d);
            case 3:
                return 2.0d * dangle_dtime;
            case 4:
                return (-dangle_dtime) * 2.0d;
            case 5:
                return (-this.mPI2) * dangle_dtime * Math.sin(this.mPI2 * angle);
            case 6:
                return dangle_dtime * 4.0d * ((((angle * 4.0d) + 2.0d) % 4.0d) - 2.0d);
            case 7:
                return this.mCustomCurve.getSlope(angle % 1.0d, 0);
            default:
                return this.mPI2 * dangle_dtime * Math.cos(this.mPI2 * angle);
        }
    }
}
