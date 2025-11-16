package androidx.constraintlayout.core.motion;

import androidx.constraintlayout.core.motion.key.MotionKeyPosition;
import androidx.constraintlayout.core.motion.utils.Easing;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;

/* loaded from: classes.dex */
public class MotionPaths implements Comparable<MotionPaths> {
    public static final int CARTESIAN = 0;
    public static final boolean DEBUG = false;
    static final int OFF_HEIGHT = 4;
    static final int OFF_PATH_ROTATE = 5;
    static final int OFF_POSITION = 0;
    static final int OFF_WIDTH = 3;
    static final int OFF_X = 1;
    static final int OFF_Y = 2;
    public static final boolean OLD_WAY = false;
    public static final int PERPENDICULAR = 1;
    public static final int SCREEN = 2;
    public static final String TAG = "MotionPaths";
    static String[] sNames = {"position", "x", "y", "width", "height", "pathRotate"};
    int mAnimateCircleAngleTo;
    String mAnimateRelativeTo;
    HashMap<String, CustomVariable> mCustomAttributes;
    int mDrawPath;
    float mHeight;
    public String mId;
    Easing mKeyFrameEasing;
    int mMode;
    int mPathMotionArc;
    float mPathRotate;
    float mPosition;
    float mProgress;
    float mRelativeAngle;
    Motion mRelativeToController;
    double[] mTempDelta;
    double[] mTempValue;
    float mTime;
    float mWidth;
    float mX;
    float mY;

    public MotionPaths() {
        this.mDrawPath = 0;
        this.mPathRotate = Float.NaN;
        this.mProgress = Float.NaN;
        this.mPathMotionArc = -1;
        this.mAnimateRelativeTo = null;
        this.mRelativeAngle = Float.NaN;
        this.mRelativeToController = null;
        this.mCustomAttributes = new HashMap<>();
        this.mMode = 0;
        this.mTempValue = new double[18];
        this.mTempDelta = new double[18];
    }

    void initCartesian(MotionKeyPosition c, MotionPaths startTimePoint, MotionPaths endTimePoint) {
        float position = c.mFramePosition / 100.0f;
        this.mTime = position;
        this.mDrawPath = c.mDrawPath;
        float scaleWidth = Float.isNaN(c.mPercentWidth) ? position : c.mPercentWidth;
        float scaleHeight = Float.isNaN(c.mPercentHeight) ? position : c.mPercentHeight;
        float scaleX = endTimePoint.mWidth - startTimePoint.mWidth;
        float scaleY = endTimePoint.mHeight - startTimePoint.mHeight;
        this.mPosition = this.mTime;
        float startCenterX = startTimePoint.mX + (startTimePoint.mWidth / 2.0f);
        float startCenterY = startTimePoint.mY + (startTimePoint.mHeight / 2.0f);
        float endCenterX = endTimePoint.mX + (endTimePoint.mWidth / 2.0f);
        float endCenterY = endTimePoint.mY + (endTimePoint.mHeight / 2.0f);
        float pathVectorX = endCenterX - startCenterX;
        float pathVectorY = endCenterY - startCenterY;
        this.mX = (int) ((startTimePoint.mX + (pathVectorX * position)) - ((scaleX * scaleWidth) / 2.0f));
        this.mY = (int) ((startTimePoint.mY + (pathVectorY * position)) - ((scaleY * scaleHeight) / 2.0f));
        this.mWidth = (int) (startTimePoint.mWidth + (scaleX * scaleWidth));
        this.mHeight = (int) (startTimePoint.mHeight + (scaleY * scaleHeight));
        float dxdx = Float.isNaN(c.mPercentX) ? position : c.mPercentX;
        float dxdx2 = dxdx;
        float dxdx3 = c.mAltPercentY;
        float dydx = Float.isNaN(dxdx3) ? 0.0f : c.mAltPercentY;
        float dydx2 = dydx;
        float dydx3 = c.mPercentY;
        float dydy = Float.isNaN(dydx3) ? position : c.mPercentY;
        float dydy2 = dydy;
        float dydy3 = c.mAltPercentX;
        float dxdy = Float.isNaN(dydy3) ? 0.0f : c.mAltPercentX;
        this.mMode = 0;
        this.mX = (int) (((startTimePoint.mX + (pathVectorX * dxdx2)) + (pathVectorY * dxdy)) - ((scaleX * scaleWidth) / 2.0f));
        this.mY = (int) (((startTimePoint.mY + (pathVectorX * dydx2)) + (pathVectorY * dydy2)) - ((scaleY * scaleHeight) / 2.0f));
        this.mKeyFrameEasing = Easing.getInterpolator(c.mTransitionEasing);
        this.mPathMotionArc = c.mPathMotionArc;
    }

    public MotionPaths(int parentWidth, int parentHeight, MotionKeyPosition c, MotionPaths startTimePoint, MotionPaths endTimePoint) {
        this.mDrawPath = 0;
        this.mPathRotate = Float.NaN;
        this.mProgress = Float.NaN;
        this.mPathMotionArc = -1;
        this.mAnimateRelativeTo = null;
        this.mRelativeAngle = Float.NaN;
        this.mRelativeToController = null;
        this.mCustomAttributes = new HashMap<>();
        this.mMode = 0;
        this.mTempValue = new double[18];
        this.mTempDelta = new double[18];
        if (startTimePoint.mAnimateRelativeTo != null) {
            initPolar(parentWidth, parentHeight, c, startTimePoint, endTimePoint);
        }
        switch (c.mPositionType) {
            case 1:
                initPath(c, startTimePoint, endTimePoint);
                break;
            case 2:
                initScreen(parentWidth, parentHeight, c, startTimePoint, endTimePoint);
                break;
            default:
                initCartesian(c, startTimePoint, endTimePoint);
                break;
        }
    }

    void initPolar(int parentWidth, int parentHeight, MotionKeyPosition c, MotionPaths s, MotionPaths e) {
        float position = c.mFramePosition / 100.0f;
        this.mTime = position;
        this.mDrawPath = c.mDrawPath;
        this.mMode = c.mPositionType;
        float scaleWidth = Float.isNaN(c.mPercentWidth) ? position : c.mPercentWidth;
        float scaleHeight = Float.isNaN(c.mPercentHeight) ? position : c.mPercentHeight;
        float scaleX = e.mWidth - s.mWidth;
        float scaleY = e.mHeight - s.mHeight;
        this.mPosition = this.mTime;
        this.mWidth = (int) (s.mWidth + (scaleX * scaleWidth));
        this.mHeight = (int) (s.mHeight + (scaleY * scaleHeight));
        float f = 1.0f - position;
        switch (c.mPositionType) {
            case 1:
                this.mX = ((Float.isNaN(c.mPercentX) ? position : c.mPercentX) * (e.mX - s.mX)) + s.mX;
                this.mY = ((Float.isNaN(c.mPercentY) ? position : c.mPercentY) * (e.mY - s.mY)) + s.mY;
                break;
            case 2:
                this.mX = Float.isNaN(c.mPercentX) ? ((e.mX - s.mX) * position) + s.mX : c.mPercentX * Math.min(scaleHeight, scaleWidth);
                this.mY = Float.isNaN(c.mPercentY) ? ((e.mY - s.mY) * position) + s.mY : c.mPercentY;
                break;
            default:
                this.mX = ((Float.isNaN(c.mPercentX) ? position : c.mPercentX) * (e.mX - s.mX)) + s.mX;
                this.mY = ((Float.isNaN(c.mPercentY) ? position : c.mPercentY) * (e.mY - s.mY)) + s.mY;
                break;
        }
        this.mAnimateRelativeTo = s.mAnimateRelativeTo;
        this.mKeyFrameEasing = Easing.getInterpolator(c.mTransitionEasing);
        this.mPathMotionArc = c.mPathMotionArc;
    }

    public void setupRelative(Motion mc, MotionPaths relative) {
        double dx = ((this.mX + (this.mWidth / 2.0f)) - relative.mX) - (relative.mWidth / 2.0f);
        double dy = ((this.mY + (this.mHeight / 2.0f)) - relative.mY) - (relative.mHeight / 2.0f);
        this.mRelativeToController = mc;
        this.mX = (float) Math.hypot(dy, dx);
        if (Float.isNaN(this.mRelativeAngle)) {
            this.mY = (float) (Math.atan2(dy, dx) + 1.5707963267948966d);
        } else {
            this.mY = (float) Math.toRadians(this.mRelativeAngle);
        }
    }

    void initScreen(int parentWidth, int parentHeight, MotionKeyPosition c, MotionPaths startTimePoint, MotionPaths endTimePoint) {
        int parentWidth2;
        float position = c.mFramePosition / 100.0f;
        this.mTime = position;
        this.mDrawPath = c.mDrawPath;
        float scaleWidth = Float.isNaN(c.mPercentWidth) ? position : c.mPercentWidth;
        float scaleHeight = Float.isNaN(c.mPercentHeight) ? position : c.mPercentHeight;
        float scaleX = endTimePoint.mWidth - startTimePoint.mWidth;
        float scaleY = endTimePoint.mHeight - startTimePoint.mHeight;
        this.mPosition = this.mTime;
        float startCenterX = startTimePoint.mX + (startTimePoint.mWidth / 2.0f);
        float startCenterY = startTimePoint.mY + (startTimePoint.mHeight / 2.0f);
        float endCenterX = endTimePoint.mX + (endTimePoint.mWidth / 2.0f);
        float endCenterY = endTimePoint.mY + (endTimePoint.mHeight / 2.0f);
        float pathVectorX = endCenterX - startCenterX;
        float pathVectorY = endCenterY - startCenterY;
        this.mX = (int) ((startTimePoint.mX + (pathVectorX * position)) - ((scaleX * scaleWidth) / 2.0f));
        this.mY = (int) ((startTimePoint.mY + (pathVectorY * position)) - ((scaleY * scaleHeight) / 2.0f));
        this.mWidth = (int) (startTimePoint.mWidth + (scaleX * scaleWidth));
        this.mHeight = (int) (startTimePoint.mHeight + (scaleY * scaleHeight));
        this.mMode = 2;
        if (Float.isNaN(c.mPercentX)) {
            parentWidth2 = parentWidth;
        } else {
            parentWidth2 = parentWidth - ((int) this.mWidth);
            this.mX = (int) (parentWidth2 * c.mPercentX);
        }
        if (!Float.isNaN(c.mPercentY)) {
            this.mY = (int) ((parentHeight - ((int) this.mHeight)) * c.mPercentY);
        }
        this.mAnimateRelativeTo = this.mAnimateRelativeTo;
        this.mKeyFrameEasing = Easing.getInterpolator(c.mTransitionEasing);
        this.mPathMotionArc = c.mPathMotionArc;
    }

    void initPath(MotionKeyPosition c, MotionPaths startTimePoint, MotionPaths endTimePoint) {
        float position = c.mFramePosition / 100.0f;
        this.mTime = position;
        this.mDrawPath = c.mDrawPath;
        float scaleWidth = Float.isNaN(c.mPercentWidth) ? position : c.mPercentWidth;
        float scaleHeight = Float.isNaN(c.mPercentHeight) ? position : c.mPercentHeight;
        float scaleX = endTimePoint.mWidth - startTimePoint.mWidth;
        float scaleY = endTimePoint.mHeight - startTimePoint.mHeight;
        this.mPosition = this.mTime;
        float path = Float.isNaN(c.mPercentX) ? position : c.mPercentX;
        float startCenterX = startTimePoint.mX + (startTimePoint.mWidth / 2.0f);
        float startCenterY = startTimePoint.mY + (startTimePoint.mHeight / 2.0f);
        float endCenterX = endTimePoint.mX + (endTimePoint.mWidth / 2.0f);
        float endCenterY = endTimePoint.mY + (endTimePoint.mHeight / 2.0f);
        float pathVectorX = endCenterX - startCenterX;
        float pathVectorY = endCenterY - startCenterY;
        this.mX = (int) ((startTimePoint.mX + (pathVectorX * path)) - ((scaleX * scaleWidth) / 2.0f));
        this.mY = (int) ((startTimePoint.mY + (pathVectorY * path)) - ((scaleY * scaleHeight) / 2.0f));
        this.mWidth = (int) (startTimePoint.mWidth + (scaleX * scaleWidth));
        this.mHeight = (int) (startTimePoint.mHeight + (scaleY * scaleHeight));
        float perpendicular = Float.isNaN(c.mPercentY) ? 0.0f : c.mPercentY;
        float normalX = (-pathVectorY) * perpendicular;
        float normalY = pathVectorX * perpendicular;
        this.mMode = 1;
        this.mX = (int) ((startTimePoint.mX + (pathVectorX * path)) - ((scaleX * scaleWidth) / 2.0f));
        this.mY = (int) ((startTimePoint.mY + (pathVectorY * path)) - ((scaleY * scaleHeight) / 2.0f));
        this.mX += normalX;
        this.mY += normalY;
        this.mAnimateRelativeTo = this.mAnimateRelativeTo;
        this.mKeyFrameEasing = Easing.getInterpolator(c.mTransitionEasing);
        this.mPathMotionArc = c.mPathMotionArc;
    }

    private static float xRotate(float sin, float cos, float cx, float cy, float x, float y) {
        return (((x - cx) * cos) - ((y - cy) * sin)) + cx;
    }

    private static float yRotate(float sin, float cos, float cx, float cy, float x, float y) {
        return ((x - cx) * sin) + ((y - cy) * cos) + cy;
    }

    private boolean diff(float a, float b) {
        return (Float.isNaN(a) || Float.isNaN(b)) ? Float.isNaN(a) != Float.isNaN(b) : Math.abs(a - b) > 1.0E-6f;
    }

    void different(MotionPaths points, boolean[] mask, String[] custom, boolean arcMode) {
        boolean diffx = diff(this.mX, points.mX);
        boolean diffy = diff(this.mY, points.mY);
        int c = 0 + 1;
        mask[0] = mask[0] | diff(this.mPosition, points.mPosition);
        int c2 = c + 1;
        mask[c] = mask[c] | (diffx || diffy || arcMode);
        int c3 = c2 + 1;
        mask[c2] = mask[c2] | (diffx || diffy || arcMode);
        int c4 = c3 + 1;
        mask[c3] = mask[c3] | diff(this.mWidth, points.mWidth);
        int i = c4 + 1;
        mask[c4] = mask[c4] | diff(this.mHeight, points.mHeight);
    }

    void getCenter(double p, int[] toUse, double[] data, float[] point, int offset) {
        float f;
        float v_x = this.mX;
        float v_y = this.mY;
        float v_width = this.mWidth;
        float v_height = this.mHeight;
        for (int i = 0; i < toUse.length; i++) {
            float value = (float) data[i];
            switch (toUse[i]) {
                case 1:
                    v_x = value;
                    break;
                case 2:
                    v_y = value;
                    break;
                case 3:
                    v_width = value;
                    break;
                case 4:
                    v_height = value;
                    break;
            }
        }
        if (this.mRelativeToController != null) {
            float[] pos = new float[2];
            float[] vel = new float[2];
            this.mRelativeToController.getCenter(p, pos, vel);
            float rx = pos[0];
            float ry = pos[1];
            float radius = v_x;
            float angle = v_y;
            f = 2.0f;
            float v_x2 = (float) ((rx + (Math.sin(angle) * radius)) - (v_width / 2.0f));
            v_y = (float) ((ry - (Math.cos(angle) * radius)) - (v_height / 2.0f));
            v_x = v_x2;
        } else {
            f = 2.0f;
        }
        point[offset] = (v_width / f) + v_x + 0.0f;
        point[offset + 1] = (v_height / f) + v_y + 0.0f;
    }

    void getCenter(double p, int[] toUse, double[] data, float[] point, double[] vdata, float[] velocity) {
        float v_width;
        float v_height;
        float f;
        float v_x = this.mX;
        float v_y = this.mY;
        float v_width2 = this.mWidth;
        float v_height2 = this.mHeight;
        float dv_x = 0.0f;
        float dv_y = 0.0f;
        float dv_width = 0.0f;
        float dv_height = 0.0f;
        for (int i = 0; i < toUse.length; i++) {
            float value = (float) data[i];
            float dvalue = (float) vdata[i];
            switch (toUse[i]) {
                case 1:
                    v_x = value;
                    dv_x = dvalue;
                    break;
                case 2:
                    v_y = value;
                    dv_y = dvalue;
                    break;
                case 3:
                    v_width2 = value;
                    dv_width = dvalue;
                    break;
                case 4:
                    v_height2 = value;
                    dv_height = dvalue;
                    break;
            }
        }
        float dpos_x = (dv_width / 2.0f) + dv_x;
        float dpos_y = (dv_height / 2.0f) + dv_y;
        if (this.mRelativeToController != null) {
            f = 2.0f;
            float[] pos = new float[2];
            float[] vel = new float[2];
            float v_x2 = v_x;
            float v_y2 = v_y;
            this.mRelativeToController.getCenter(p, pos, vel);
            float rx = pos[0];
            float ry = pos[1];
            float dradius = dv_x;
            float dangle = dv_y;
            float drx = vel[0];
            float dry = vel[1];
            v_width = v_width2;
            v_height = v_height2;
            float v_x3 = (float) ((rx + (Math.sin(v_y2) * v_x2)) - (v_width / 2.0f));
            float v_y3 = (float) ((ry - (v_x2 * Math.cos(v_y2))) - (v_height / 2.0f));
            dpos_x = (float) (drx + (Math.sin(v_y2) * dradius) + (dangle * Math.cos(v_y2)));
            dpos_y = (float) ((dry - (dradius * Math.cos(v_y2))) + (dangle * Math.sin(v_y2)));
            v_x = v_x3;
            v_y = v_y3;
        } else {
            v_width = v_width2;
            v_height = v_height2;
            f = 2.0f;
        }
        point[0] = (v_width / f) + v_x + 0.0f;
        point[1] = (v_height / f) + v_y + 0.0f;
        velocity[0] = dpos_x;
        velocity[1] = dpos_y;
    }

    void getCenterVelocity(double p, int[] toUse, double[] data, float[] point, int offset) {
        float f;
        float v_x = this.mX;
        float v_y = this.mY;
        float v_width = this.mWidth;
        float v_height = this.mHeight;
        for (int i = 0; i < toUse.length; i++) {
            float value = (float) data[i];
            switch (toUse[i]) {
                case 1:
                    v_x = value;
                    break;
                case 2:
                    v_y = value;
                    break;
                case 3:
                    v_width = value;
                    break;
                case 4:
                    v_height = value;
                    break;
            }
        }
        if (this.mRelativeToController != null) {
            float[] pos = new float[2];
            float[] vel = new float[2];
            this.mRelativeToController.getCenter(p, pos, vel);
            float rx = pos[0];
            float ry = pos[1];
            float radius = v_x;
            float angle = v_y;
            f = 2.0f;
            float v_x2 = (float) ((rx + (Math.sin(angle) * radius)) - (v_width / 2.0f));
            v_y = (float) ((ry - (Math.cos(angle) * radius)) - (v_height / 2.0f));
            v_x = v_x2;
        } else {
            f = 2.0f;
        }
        point[offset] = (v_width / f) + v_x + 0.0f;
        point[offset + 1] = (v_height / f) + v_y + 0.0f;
    }

    void getBounds(int[] toUse, double[] data, float[] point, int offset) {
        float f = this.mX;
        float f2 = this.mY;
        float v_width = this.mWidth;
        float v_height = this.mHeight;
        for (int i = 0; i < toUse.length; i++) {
            float value = (float) data[i];
            switch (toUse[i]) {
                case 3:
                    v_width = value;
                    break;
                case 4:
                    v_height = value;
                    break;
            }
        }
        point[offset] = v_width;
        point[offset + 1] = v_height;
    }

    void setView(float position, MotionWidget view, int[] toUse, double[] data, double[] slope, double[] cycle) {
        char c;
        float v_width;
        float v_height;
        float dv_x;
        int i;
        float v_y;
        double d;
        float v_x = this.mX;
        float v_y2 = this.mY;
        float v_width2 = this.mWidth;
        float v_height2 = this.mHeight;
        float dv_x2 = 0.0f;
        float dv_y = 0.0f;
        float dv_width = 0.0f;
        float dv_height = 0.0f;
        float path_rotate = Float.NaN;
        if (toUse.length != 0) {
            c = 1;
            if (this.mTempValue.length <= toUse[toUse.length - 1]) {
                int scratch_data_length = toUse[toUse.length - 1] + 1;
                this.mTempValue = new double[scratch_data_length];
                this.mTempDelta = new double[scratch_data_length];
            }
        } else {
            c = 1;
        }
        float v_x2 = v_x;
        Arrays.fill(this.mTempValue, Double.NaN);
        for (int i2 = 0; i2 < toUse.length; i2++) {
            this.mTempValue[toUse[i2]] = data[i2];
            this.mTempDelta[toUse[i2]] = slope[i2];
        }
        int i3 = 0;
        float v_y3 = v_y2;
        while (i3 < this.mTempValue.length) {
            if (Double.isNaN(this.mTempValue[i3]) && (cycle == null || cycle[i3] == 0.0d)) {
                i = i3;
                v_y = v_y3;
            } else {
                double deltaCycle = cycle != null ? cycle[i3] : 0.0d;
                if (!Double.isNaN(this.mTempValue[i3])) {
                    i = i3;
                    v_y = v_y3;
                    d = this.mTempValue[i3] + deltaCycle;
                } else {
                    i = i3;
                    v_y = v_y3;
                    d = deltaCycle;
                }
                float value = (float) d;
                float dvalue = (float) this.mTempDelta[i];
                switch (i) {
                    case 0:
                        v_y3 = v_y;
                        break;
                    case 1:
                        dv_x2 = dvalue;
                        v_x2 = value;
                        v_y3 = v_y;
                        break;
                    case 2:
                        v_y3 = value;
                        dv_y = dvalue;
                        break;
                    case 3:
                        dv_width = dvalue;
                        v_width2 = value;
                        v_y3 = v_y;
                        break;
                    case 4:
                        dv_height = dvalue;
                        v_height2 = value;
                        v_y3 = v_y;
                        break;
                    case 5:
                        path_rotate = value;
                        v_y3 = v_y;
                        break;
                }
                i3 = i + 1;
            }
            v_y3 = v_y;
            i3 = i + 1;
        }
        float v_y4 = v_y3;
        if (this.mRelativeToController != null) {
            float[] pos = new float[2];
            float[] vel = new float[2];
            v_width = v_width2;
            v_height = v_height2;
            this.mRelativeToController.getCenter(position, pos, vel);
            float rx = pos[0];
            float ry = pos[c];
            float radius = v_x2;
            float dradius = dv_x2;
            float dangle = dv_y;
            float drx = vel[0];
            float dry = vel[c];
            float pos_x = (float) ((rx + (Math.sin(v_y4) * radius)) - (v_width / 2.0f));
            float pos_y = (float) ((ry - (Math.cos(v_y4) * radius)) - (v_height / 2.0f));
            float dpos_x = (float) (drx + (Math.sin(v_y4) * dradius) + (dangle * Math.cos(v_y4) * radius));
            float dpos_y = (float) ((dry - (dradius * Math.cos(v_y4))) + (Math.sin(v_y4) * radius * dangle));
            v_x2 = pos_x;
            if (slope.length >= 2) {
                slope[0] = dpos_x;
                slope[c] = dpos_y;
            }
            if (!Float.isNaN(path_rotate)) {
                float rot = (float) (path_rotate + Math.toDegrees(Math.atan2(dpos_y, dpos_x)));
                view.setRotationZ(rot);
            }
            dv_x = pos_y;
        } else {
            v_width = v_width2;
            v_height = v_height2;
            float dv_x3 = dv_x2;
            float dv_y2 = dv_y;
            float dv_width2 = dv_width;
            float dv_height2 = dv_height;
            if (!Float.isNaN(path_rotate)) {
                float dx = dv_x3 + (dv_width2 / 2.0f);
                float dy = dv_y2 + (dv_height2 / 2.0f);
                float rot2 = 0.0f + ((float) (path_rotate + Math.toDegrees(Math.atan2(dy, dx))));
                view.setRotationZ(rot2);
            }
            dv_x = v_y4;
        }
        int l = (int) (v_x2 + 0.5f);
        int t = (int) (dv_x + 0.5f);
        int r = (int) (v_x2 + 0.5f + v_width);
        int b = (int) (0.5f + dv_x + v_height);
        int i4 = r - l;
        int i5 = b - t;
        view.layout(l, t, r, b);
    }

    void getRect(int[] toUse, double[] data, float[] path, int offset) {
        float ry;
        float v_height;
        float f;
        float angle;
        float v_x;
        float cx;
        float cy;
        float x1;
        float y1;
        float x4;
        float y4;
        int[] iArr = toUse;
        float v_x2 = this.mX;
        float v_y = this.mY;
        float v_width = this.mWidth;
        float v_height2 = this.mHeight;
        float v_x3 = v_x2;
        int i = 0;
        while (true) {
            float v_y2 = v_y;
            if (i < iArr.length) {
                int i2 = i;
                float value = (float) data[i2];
                switch (toUse[i2]) {
                    case 1:
                        v_x3 = value;
                        break;
                    case 2:
                        v_y2 = value;
                        break;
                    case 3:
                        v_width = value;
                        break;
                    case 4:
                        v_height2 = value;
                        break;
                }
                i = i2 + 1;
                iArr = toUse;
                v_y = v_y2;
            } else {
                if (this.mRelativeToController == null) {
                    ry = v_width;
                    v_height = v_height2;
                    f = 2.0f;
                    angle = v_y2;
                    v_x = v_x3;
                } else {
                    float rx = this.mRelativeToController.getCenterX();
                    float ry2 = this.mRelativeToController.getCenterY();
                    float radius = v_x3;
                    f = 2.0f;
                    float v_x4 = (float) ((rx + (Math.sin(v_y2) * radius)) - (v_width / 2.0f));
                    v_height = v_height2;
                    ry = v_width;
                    angle = (float) ((ry2 - (radius * Math.cos(v_y2))) - (v_height / 2.0f));
                    v_x = v_x4;
                }
                float x12 = v_x;
                float y12 = angle;
                float x2 = v_x + ry;
                float y2 = y12;
                float x3 = x2;
                float y3 = angle + v_height;
                float x42 = x12;
                float y42 = y3;
                float cx2 = x12 + (ry / f);
                float cy2 = y12 + (v_height / f);
                if (!Float.isNaN(Float.NaN)) {
                    float cx3 = x12 + ((x2 - x12) * Float.NaN);
                    cx = cx3;
                } else {
                    cx = cx2;
                }
                if (!Float.isNaN(Float.NaN)) {
                    float cy3 = y12 + ((y3 - y12) * Float.NaN);
                    cy = cy3;
                } else {
                    cy = cy2;
                }
                if (1.0f == 1.0f) {
                    x1 = x12;
                } else {
                    float midx = (x12 + x2) / f;
                    x2 = ((x2 - midx) * 1.0f) + midx;
                    x3 = ((x3 - midx) * 1.0f) + midx;
                    x42 = ((x42 - midx) * 1.0f) + midx;
                    x1 = ((x12 - midx) * 1.0f) + midx;
                }
                if (1.0f == 1.0f) {
                    y1 = y12;
                } else {
                    float midy = (y12 + y3) / f;
                    y2 = ((y2 - midy) * 1.0f) + midy;
                    y3 = ((y3 - midy) * 1.0f) + midy;
                    y42 = ((y42 - midy) * 1.0f) + midy;
                    y1 = ((y12 - midy) * 1.0f) + midy;
                }
                if (0.0f != 0.0f) {
                    float sin = (float) Math.sin(Math.toRadians(0.0f));
                    float cos = (float) Math.cos(Math.toRadians(0.0f));
                    float tx1 = xRotate(sin, cos, cx, cy, x1, y1);
                    float ty1 = yRotate(sin, cos, cx, cy, x1, y1);
                    float x13 = x2;
                    float y22 = y2;
                    x2 = xRotate(sin, cos, cx, cy, x13, y22);
                    y2 = yRotate(sin, cos, cx, cy, x13, y22);
                    float x22 = x3;
                    float y32 = y3;
                    x3 = xRotate(sin, cos, cx, cy, x22, y32);
                    y3 = yRotate(sin, cos, cx, cy, x22, y32);
                    float x32 = x42;
                    float y43 = y42;
                    x42 = xRotate(sin, cos, cx, cy, x32, y43);
                    y42 = yRotate(sin, cos, cx, cy, x32, y43);
                    x4 = tx1;
                    y4 = ty1;
                } else {
                    x4 = x1;
                    y4 = y1;
                }
                int offset2 = offset + 1;
                path[offset] = x4 + 0.0f;
                int offset3 = offset2 + 1;
                path[offset2] = y4 + 0.0f;
                int offset4 = offset3 + 1;
                path[offset3] = x2 + 0.0f;
                int offset5 = offset4 + 1;
                path[offset4] = y2 + 0.0f;
                int offset6 = offset5 + 1;
                path[offset5] = x3 + 0.0f;
                int offset7 = offset6 + 1;
                path[offset6] = y3 + 0.0f;
                int offset8 = offset7 + 1;
                path[offset7] = x42 + 0.0f;
                int i3 = offset8 + 1;
                path[offset8] = y42 + 0.0f;
                return;
            }
        }
    }

    void setDpDt(float locationX, float locationY, float[] mAnchorDpDt, int[] toUse, double[] deltaData, double[] data) {
        float d_x = 0.0f;
        float d_y = 0.0f;
        float d_width = 0.0f;
        float d_height = 0.0f;
        for (int i = 0; i < toUse.length; i++) {
            float deltaV = (float) deltaData[i];
            switch (toUse[i]) {
                case 1:
                    d_x = deltaV;
                    break;
                case 2:
                    d_y = deltaV;
                    break;
                case 3:
                    d_width = deltaV;
                    break;
                case 4:
                    d_height = deltaV;
                    break;
            }
        }
        float deltaX = d_x - ((0.0f * d_width) / 2.0f);
        float deltaY = d_y - ((0.0f * d_height) / 2.0f);
        float deltaWidth = (0.0f + 1.0f) * d_width;
        float deltaHeight = (0.0f + 1.0f) * d_height;
        float deltaRight = deltaX + deltaWidth;
        float deltaBottom = deltaY + deltaHeight;
        mAnchorDpDt[0] = ((1.0f - locationX) * deltaX) + (deltaRight * locationX) + 0.0f;
        mAnchorDpDt[1] = ((1.0f - locationY) * deltaY) + (deltaBottom * locationY) + 0.0f;
    }

    void fillStandard(double[] data, int[] toUse) {
        float[] set = {this.mPosition, this.mX, this.mY, this.mWidth, this.mHeight, this.mPathRotate};
        int c = 0;
        for (int i = 0; i < toUse.length; i++) {
            if (toUse[i] < set.length) {
                data[c] = set[toUse[i]];
                c++;
            }
        }
    }

    boolean hasCustomData(String name) {
        return this.mCustomAttributes.containsKey(name);
    }

    int getCustomDataCount(String name) {
        CustomVariable a = this.mCustomAttributes.get(name);
        if (a == null) {
            return 0;
        }
        return a.numberOfInterpolatedValues();
    }

    int getCustomData(String name, double[] value, int offset) {
        CustomVariable a = this.mCustomAttributes.get(name);
        if (a == null) {
            return 0;
        }
        if (a.numberOfInterpolatedValues() == 1) {
            value[offset] = a.getValueToInterpolate();
            return 1;
        }
        int n = a.numberOfInterpolatedValues();
        float[] f = new float[n];
        a.getValuesToInterpolate(f);
        int i = 0;
        while (i < n) {
            value[offset] = f[i];
            i++;
            offset++;
        }
        return n;
    }

    void setBounds(float x, float y, float w, float h) {
        this.mX = x;
        this.mY = y;
        this.mWidth = w;
        this.mHeight = h;
    }

    @Override // java.lang.Comparable
    public int compareTo(MotionPaths o) {
        return Float.compare(this.mPosition, o.mPosition);
    }

    public void applyParameters(MotionWidget c) {
        this.mKeyFrameEasing = Easing.getInterpolator(c.mMotion.mTransitionEasing);
        this.mPathMotionArc = c.mMotion.mPathMotionArc;
        this.mAnimateRelativeTo = c.mMotion.mAnimateRelativeTo;
        this.mPathRotate = c.mMotion.mPathRotate;
        this.mDrawPath = c.mMotion.mDrawPath;
        this.mAnimateCircleAngleTo = c.mMotion.mAnimateCircleAngleTo;
        this.mProgress = c.mPropertySet.mProgress;
        if (c.mWidgetFrame != null && c.mWidgetFrame.widget != null) {
            this.mRelativeAngle = c.mWidgetFrame.widget.mCircleConstraintAngle;
        }
        Set<String> at = c.getCustomAttributeNames();
        for (String s : at) {
            CustomVariable attr = c.getCustomAttribute(s);
            if (attr != null && attr.isContinuous()) {
                this.mCustomAttributes.put(s, attr);
            }
        }
    }

    public void configureRelativeTo(Motion toOrbit) {
        toOrbit.getPos(this.mProgress);
    }
}
