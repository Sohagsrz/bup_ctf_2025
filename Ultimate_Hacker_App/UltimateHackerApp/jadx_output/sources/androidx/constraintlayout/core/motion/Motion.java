package androidx.constraintlayout.core.motion;

import androidx.constraintlayout.core.motion.key.MotionKey;
import androidx.constraintlayout.core.motion.key.MotionKeyAttributes;
import androidx.constraintlayout.core.motion.key.MotionKeyCycle;
import androidx.constraintlayout.core.motion.key.MotionKeyPosition;
import androidx.constraintlayout.core.motion.key.MotionKeyTimeCycle;
import androidx.constraintlayout.core.motion.key.MotionKeyTrigger;
import androidx.constraintlayout.core.motion.utils.CurveFit;
import androidx.constraintlayout.core.motion.utils.DifferentialInterpolator;
import androidx.constraintlayout.core.motion.utils.Easing;
import androidx.constraintlayout.core.motion.utils.FloatRect;
import androidx.constraintlayout.core.motion.utils.KeyCache;
import androidx.constraintlayout.core.motion.utils.KeyCycleOscillator;
import androidx.constraintlayout.core.motion.utils.KeyFrameArray;
import androidx.constraintlayout.core.motion.utils.Rect;
import androidx.constraintlayout.core.motion.utils.SplineSet;
import androidx.constraintlayout.core.motion.utils.TimeCycleSplineSet;
import androidx.constraintlayout.core.motion.utils.TypedBundle;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.motion.utils.Utils;
import androidx.constraintlayout.core.motion.utils.VelocityMatrix;
import androidx.constraintlayout.core.motion.utils.ViewState;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public class Motion implements TypedValues {
    static final int BOUNCE = 4;
    private static final boolean DEBUG = false;
    public static final int DRAW_PATH_AS_CONFIGURED = 4;
    public static final int DRAW_PATH_BASIC = 1;
    public static final int DRAW_PATH_CARTESIAN = 3;
    public static final int DRAW_PATH_NONE = 0;
    public static final int DRAW_PATH_RECTANGLE = 5;
    public static final int DRAW_PATH_RELATIVE = 2;
    public static final int DRAW_PATH_SCREEN = 6;
    static final int EASE_IN = 1;
    static final int EASE_IN_OUT = 0;
    static final int EASE_OUT = 2;
    private static final boolean FAVOR_FIXED_SIZE_VIEWS = false;
    public static final int HORIZONTAL_PATH_X = 2;
    public static final int HORIZONTAL_PATH_Y = 3;
    private static final int INTERPOLATOR_REFERENCE_ID = -2;
    private static final int INTERPOLATOR_UNDEFINED = -3;
    static final int LINEAR = 3;
    static final int OVERSHOOT = 5;
    public static final int PATH_PERCENT = 0;
    public static final int PATH_PERPENDICULAR = 1;
    public static final int ROTATION_LEFT = 2;
    public static final int ROTATION_RIGHT = 1;
    private static final int SPLINE_STRING = -1;
    private static final String TAG = "MotionController";
    public static final int VERTICAL_PATH_X = 4;
    public static final int VERTICAL_PATH_Y = 5;
    private CurveFit mArcSpline;
    private int[] mAttributeInterpolatorCount;
    private String[] mAttributeNames;
    String[] mAttributeTable;
    private HashMap<String, SplineSet> mAttributesMap;
    String mConstraintTag;
    float mCurrentCenterX;
    float mCurrentCenterY;
    private HashMap<String, KeyCycleOscillator> mCycleMap;
    public String mId;
    private double[] mInterpolateData;
    private int[] mInterpolateVariables;
    private double[] mInterpolateVelocity;
    private MotionKeyTrigger[] mKeyTriggers;
    Motion mRelativeMotion;
    private CurveFit[] mSpline;
    private HashMap<String, TimeCycleSplineSet> mTimeCycleAttributesMap;
    MotionWidget mView;
    Rect mTempRect = new Rect();
    private int mCurveFitType = 0;
    private MotionPaths mStartMotionPath = new MotionPaths();
    private MotionPaths mEndMotionPath = new MotionPaths();
    private MotionConstrainedPoint mStartPoint = new MotionConstrainedPoint();
    private MotionConstrainedPoint mEndPoint = new MotionConstrainedPoint();
    float mMotionStagger = Float.NaN;
    float mStaggerOffset = 0.0f;
    float mStaggerScale = 1.0f;
    private int mMaxDimension = 4;
    private float[] mValuesBuff = new float[this.mMaxDimension];
    private ArrayList<MotionPaths> mMotionPaths = new ArrayList<>();
    private float[] mVelocity = new float[1];
    private ArrayList<MotionKey> mKeyList = new ArrayList<>();
    private int mPathMotionArc = -1;
    private int mTransformPivotTarget = -1;
    private MotionWidget mTransformPivotView = null;
    private int mQuantizeMotionSteps = -1;
    private float mQuantizeMotionPhase = Float.NaN;
    private DifferentialInterpolator mQuantizeMotionInterpolator = null;
    private boolean mNoMovement = false;

    public int getTransformPivotTarget() {
        return this.mTransformPivotTarget;
    }

    public void setTransformPivotTarget(int transformPivotTarget) {
        this.mTransformPivotTarget = transformPivotTarget;
        this.mTransformPivotView = null;
    }

    public MotionPaths getKeyFrame(int i) {
        return this.mMotionPaths.get(i);
    }

    public Motion(MotionWidget view) {
        setView(view);
    }

    public float getStartX() {
        return this.mStartMotionPath.mX;
    }

    public float getStartY() {
        return this.mStartMotionPath.mY;
    }

    public float getFinalX() {
        return this.mEndMotionPath.mX;
    }

    public float getFinalY() {
        return this.mEndMotionPath.mY;
    }

    public float getStartWidth() {
        return this.mStartMotionPath.mWidth;
    }

    public float getStartHeight() {
        return this.mStartMotionPath.mHeight;
    }

    public float getFinalWidth() {
        return this.mEndMotionPath.mWidth;
    }

    public float getFinalHeight() {
        return this.mEndMotionPath.mHeight;
    }

    public String getAnimateRelativeTo() {
        return this.mStartMotionPath.mAnimateRelativeTo;
    }

    public void setupRelative(Motion motionController) {
        this.mRelativeMotion = motionController;
    }

    private void setupRelative() {
        if (this.mRelativeMotion == null) {
            return;
        }
        this.mStartMotionPath.setupRelative(this.mRelativeMotion, this.mRelativeMotion.mStartMotionPath);
        this.mEndMotionPath.setupRelative(this.mRelativeMotion, this.mRelativeMotion.mEndMotionPath);
    }

    public float getCenterX() {
        return this.mCurrentCenterX;
    }

    public float getCenterY() {
        return this.mCurrentCenterY;
    }

    public void getCenter(double p, float[] pos, float[] vel) {
        double[] position = new double[4];
        double[] velocity = new double[4];
        this.mSpline[0].getPos(p, position);
        this.mSpline[0].getSlope(p, velocity);
        Arrays.fill(vel, 0.0f);
        this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, position, pos, velocity, vel);
    }

    public void buildPath(float[] points, int pointCount) {
        float mils;
        int i = pointCount;
        float f = 1.0f;
        float mils2 = 1.0f / (i - 1);
        SplineSet trans_x = this.mAttributesMap == null ? null : this.mAttributesMap.get("translationX");
        SplineSet trans_y = this.mAttributesMap == null ? null : this.mAttributesMap.get("translationY");
        KeyCycleOscillator osc_x = this.mCycleMap == null ? null : this.mCycleMap.get("translationX");
        KeyCycleOscillator osc_y = this.mCycleMap != null ? this.mCycleMap.get("translationY") : null;
        int i2 = 0;
        while (i2 < i) {
            float position = i2 * mils2;
            if (this.mStaggerScale != f) {
                if (position < this.mStaggerOffset) {
                    position = 0.0f;
                }
                if (position > this.mStaggerOffset && position < 1.0d) {
                    position = Math.min((position - this.mStaggerOffset) * this.mStaggerScale, f);
                }
            }
            double p = position;
            Easing easing = this.mStartMotionPath.mKeyFrameEasing;
            float start = 0.0f;
            float end = Float.NaN;
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                if (frame.mKeyFrameEasing != null) {
                    if (frame.mTime < position) {
                        Easing easing2 = frame.mKeyFrameEasing;
                        start = frame.mTime;
                        easing = easing2;
                    } else if (Float.isNaN(end)) {
                        end = frame.mTime;
                    }
                }
            }
            if (easing == null) {
                mils = mils2;
            } else {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                float offset = (position - start) / (end - start);
                mils = mils2;
                p = ((end - start) * ((float) easing.get(offset))) + start;
            }
            this.mSpline[0].getPos(p, this.mInterpolateData);
            if (this.mArcSpline != null && this.mInterpolateData.length > 0) {
                this.mArcSpline.getPos(p, this.mInterpolateData);
            }
            this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, this.mInterpolateData, points, i2 * 2);
            if (osc_x != null) {
                int i3 = i2 * 2;
                points[i3] = points[i3] + osc_x.get(position);
            } else if (trans_x != null) {
                int i4 = i2 * 2;
                points[i4] = points[i4] + trans_x.get(position);
            }
            if (osc_y != null) {
                int i5 = (i2 * 2) + 1;
                points[i5] = points[i5] + osc_y.get(position);
            } else if (trans_y != null) {
                int i6 = (i2 * 2) + 1;
                points[i6] = points[i6] + trans_y.get(position);
            }
            i2++;
            i = pointCount;
            mils2 = mils;
            f = 1.0f;
        }
    }

    double[] getPos(double position) {
        this.mSpline[0].getPos(position, this.mInterpolateData);
        if (this.mArcSpline != null && this.mInterpolateData.length > 0) {
            this.mArcSpline.getPos(position, this.mInterpolateData);
        }
        return this.mInterpolateData;
    }

    void buildBounds(float[] bounds, int pointCount) {
        float mils;
        Motion motion = this;
        int i = pointCount;
        float f = 1.0f;
        float mils2 = 1.0f / (i - 1);
        SplineSet trans_x = motion.mAttributesMap == null ? null : motion.mAttributesMap.get("translationX");
        if (motion.mAttributesMap != null) {
            motion.mAttributesMap.get("translationY");
        }
        if (motion.mCycleMap != null) {
            motion.mCycleMap.get("translationX");
        }
        if (motion.mCycleMap != null) {
            motion.mCycleMap.get("translationY");
        }
        int i2 = 0;
        while (i2 < i) {
            float position = i2 * mils2;
            if (motion.mStaggerScale != f) {
                if (position < motion.mStaggerOffset) {
                    position = 0.0f;
                }
                if (position > motion.mStaggerOffset && position < 1.0d) {
                    position = Math.min((position - motion.mStaggerOffset) * motion.mStaggerScale, f);
                }
            }
            double p = position;
            Easing easing = motion.mStartMotionPath.mKeyFrameEasing;
            float start = 0.0f;
            float end = Float.NaN;
            Iterator<MotionPaths> it = motion.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                if (frame.mKeyFrameEasing != null) {
                    if (frame.mTime < position) {
                        Easing easing2 = frame.mKeyFrameEasing;
                        start = frame.mTime;
                        easing = easing2;
                    } else if (Float.isNaN(end)) {
                        end = frame.mTime;
                    }
                }
            }
            if (easing == null) {
                mils = mils2;
            } else {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                float offset = (position - start) / (end - start);
                mils = mils2;
                p = ((end - start) * ((float) easing.get(offset))) + start;
            }
            motion.mSpline[0].getPos(p, motion.mInterpolateData);
            if (motion.mArcSpline != null && motion.mInterpolateData.length > 0) {
                motion.mArcSpline.getPos(p, motion.mInterpolateData);
            }
            motion.mStartMotionPath.getBounds(motion.mInterpolateVariables, motion.mInterpolateData, bounds, i2 * 2);
            i2++;
            motion = this;
            i = pointCount;
            mils2 = mils;
            trans_x = trans_x;
            f = 1.0f;
        }
    }

    private float getPreCycleDistance() {
        float sum;
        float position;
        char c;
        int pointCount = 100;
        float[] points = new float[2];
        float sum2 = 0.0f;
        float mils = 1.0f / (100 - 1);
        double x = 0.0d;
        double y = 0.0d;
        int i = 0;
        while (i < pointCount) {
            float position2 = i * mils;
            double p = position2;
            Easing easing = this.mStartMotionPath.mKeyFrameEasing;
            float end = Float.NaN;
            int pointCount2 = pointCount;
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            float start = 0.0f;
            while (it.hasNext()) {
                MotionPaths frame = it.next();
                Iterator<MotionPaths> it2 = it;
                if (frame.mKeyFrameEasing != null) {
                    if (frame.mTime < position2) {
                        Easing easing2 = frame.mKeyFrameEasing;
                        start = frame.mTime;
                        easing = easing2;
                    } else if (Float.isNaN(end)) {
                        end = frame.mTime;
                    }
                }
                it = it2;
            }
            if (easing == null) {
                sum = sum2;
                position = position2;
            } else {
                if (Float.isNaN(end)) {
                    end = 1.0f;
                }
                float offset = (position2 - start) / (end - start);
                sum = sum2;
                position = position2;
                p = ((end - start) * ((float) easing.get(offset))) + start;
            }
            this.mSpline[0].getPos(p, this.mInterpolateData);
            this.mStartMotionPath.getCenter(p, this.mInterpolateVariables, this.mInterpolateData, points, 0);
            if (i > 0) {
                c = 1;
                sum += (float) Math.hypot(y - points[1], x - points[0]);
            } else {
                c = 1;
            }
            x = points[0];
            y = points[c];
            i++;
            pointCount = pointCount2;
            sum2 = sum;
        }
        return sum2;
    }

    MotionKeyPosition getPositionKeyframe(int layoutWidth, int layoutHeight, float x, float y) {
        int layoutWidth2;
        int layoutHeight2;
        float x2;
        float y2;
        FloatRect start = new FloatRect();
        start.left = this.mStartMotionPath.mX;
        start.top = this.mStartMotionPath.mY;
        start.right = start.left + this.mStartMotionPath.mWidth;
        start.bottom = start.top + this.mStartMotionPath.mHeight;
        FloatRect end = new FloatRect();
        end.left = this.mEndMotionPath.mX;
        end.top = this.mEndMotionPath.mY;
        end.right = end.left + this.mEndMotionPath.mWidth;
        end.bottom = end.top + this.mEndMotionPath.mHeight;
        Iterator<MotionKey> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            MotionKey key = it.next();
            if (!(key instanceof MotionKeyPosition)) {
                layoutWidth2 = layoutWidth;
                layoutHeight2 = layoutHeight;
                x2 = x;
                y2 = y;
            } else {
                layoutWidth2 = layoutWidth;
                layoutHeight2 = layoutHeight;
                x2 = x;
                y2 = y;
                if (((MotionKeyPosition) key).intersects(layoutWidth2, layoutHeight2, start, end, x2, y2)) {
                    return (MotionKeyPosition) key;
                }
            }
            layoutWidth = layoutWidth2;
            layoutHeight = layoutHeight2;
            x = x2;
            y = y2;
        }
        return null;
    }

    public int buildKeyFrames(float[] keyFrames, int[] mode, int[] pos) {
        if (keyFrames == null) {
            return 0;
        }
        int count = 0;
        double[] time = this.mSpline[0].getTimePoints();
        if (mode != null) {
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths keyFrame = it.next();
                mode[count] = keyFrame.mMode;
                count++;
            }
            count = 0;
        }
        if (pos != null) {
            Iterator<MotionPaths> it2 = this.mMotionPaths.iterator();
            while (it2.hasNext()) {
                MotionPaths keyFrame2 = it2.next();
                pos[count] = (int) (keyFrame2.mPosition * 100.0f);
                count++;
            }
            count = 0;
        }
        int count2 = count;
        for (int i = 0; i < time.length; i++) {
            this.mSpline[0].getPos(time[i], this.mInterpolateData);
            this.mStartMotionPath.getCenter(time[i], this.mInterpolateVariables, this.mInterpolateData, keyFrames, count2);
            count2 += 2;
        }
        return count2 / 2;
    }

    int buildKeyBounds(float[] keyBounds, int[] mode) {
        if (keyBounds == null) {
            return 0;
        }
        int count = 0;
        double[] time = this.mSpline[0].getTimePoints();
        if (mode != null) {
            Iterator<MotionPaths> it = this.mMotionPaths.iterator();
            while (it.hasNext()) {
                MotionPaths keyFrame = it.next();
                mode[count] = keyFrame.mMode;
                count++;
            }
            count = 0;
        }
        for (double d : time) {
            this.mSpline[0].getPos(d, this.mInterpolateData);
            this.mStartMotionPath.getBounds(this.mInterpolateVariables, this.mInterpolateData, keyBounds, count);
            count += 2;
        }
        return count / 2;
    }

    int getAttributeValues(String attributeType, float[] points, int pointCount) {
        float f = 1.0f / (pointCount - 1);
        SplineSet spline = this.mAttributesMap.get(attributeType);
        if (spline == null) {
            return -1;
        }
        for (int j = 0; j < points.length; j++) {
            points[j] = spline.get(j / (points.length - 1));
        }
        int j2 = points.length;
        return j2;
    }

    public void buildRect(float p, float[] path, int offset) {
        this.mSpline[0].getPos(getAdjustedPosition(p, null), this.mInterpolateData);
        this.mStartMotionPath.getRect(this.mInterpolateVariables, this.mInterpolateData, path, offset);
    }

    void buildRectangles(float[] path, int pointCount) {
        float mils = 1.0f / (pointCount - 1);
        for (int i = 0; i < pointCount; i++) {
            float position = i * mils;
            this.mSpline[0].getPos(getAdjustedPosition(position, null), this.mInterpolateData);
            this.mStartMotionPath.getRect(this.mInterpolateVariables, this.mInterpolateData, path, i * 8);
        }
    }

    float getKeyFrameParameter(int type, float x, float y) {
        float dx = this.mEndMotionPath.mX - this.mStartMotionPath.mX;
        float dy = this.mEndMotionPath.mY - this.mStartMotionPath.mY;
        float startCenterX = this.mStartMotionPath.mX + (this.mStartMotionPath.mWidth / 2.0f);
        float startCenterY = this.mStartMotionPath.mY + (this.mStartMotionPath.mHeight / 2.0f);
        float hypotenuse = (float) Math.hypot(dx, dy);
        if (hypotenuse < 1.0E-7d) {
            return Float.NaN;
        }
        float vx = x - startCenterX;
        float vy = y - startCenterY;
        float distFromStart = (float) Math.hypot(vx, vy);
        if (distFromStart == 0.0f) {
            return 0.0f;
        }
        float pathDistance = (vx * dx) + (vy * dy);
        switch (type) {
        }
        return 0.0f;
    }

    private void insertKey(MotionPaths point) {
        MotionPaths redundant = null;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths p = it.next();
            if (point.mPosition == p.mPosition) {
                redundant = p;
            }
        }
        if (redundant != null) {
            this.mMotionPaths.remove(redundant);
        }
        int pos = Collections.binarySearch(this.mMotionPaths, point);
        if (pos == 0) {
            Utils.loge(TAG, " KeyPath position \"" + point.mPosition + "\" outside of range");
        }
        this.mMotionPaths.add((-pos) - 1, point);
    }

    void addKeys(ArrayList<MotionKey> list) {
        this.mKeyList.addAll(list);
    }

    public void addKey(MotionKey key) {
        this.mKeyList.add(key);
    }

    public void setPathMotionArc(int arc) {
        this.mPathMotionArc = arc;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r18v0 */
    /* JADX WARN: Type inference failed for: r18v1 */
    /* JADX WARN: Type inference failed for: r18v2 */
    public void setup(int parentWidth, int parentHeight, float transitionDuration, long currentTime) {
        HashSet<String> timeCycleAttributes;
        HashSet<String> cycleAttributes;
        ?? r18;
        HashMap<String, Integer> interpolation;
        int j;
        int j2;
        CustomVariable attribute;
        Iterator<String> it;
        SplineSet splineSets;
        Iterator<String> it2;
        Integer boxedCurve;
        HashSet<String> springAttributes;
        HashSet<String> timeCycleAttributes2;
        HashSet<String> cycleAttributes2;
        SplineSet splineSets2;
        HashSet<String> timeCycleAttributes3;
        HashSet<String> cycleAttributes3;
        KeyFrameArray.CustomVar attrList;
        HashSet<String> springAttributes2 = new HashSet<>();
        HashSet<String> timeCycleAttributes4 = new HashSet<>();
        HashSet<String> splineAttributes = new HashSet<>();
        HashSet<String> cycleAttributes4 = new HashSet<>();
        HashMap<String, Integer> interpolation2 = new HashMap<>();
        ArrayList<MotionKeyTrigger> triggerList = null;
        setupRelative();
        if (this.mPathMotionArc != -1 && this.mStartMotionPath.mPathMotionArc == -1) {
            this.mStartMotionPath.mPathMotionArc = this.mPathMotionArc;
        }
        this.mStartPoint.different(this.mEndPoint, splineAttributes);
        if (this.mKeyList != null) {
            Iterator<MotionKey> it3 = this.mKeyList.iterator();
            while (it3.hasNext()) {
                MotionKey key = it3.next();
                if (key instanceof MotionKeyPosition) {
                    MotionKeyPosition keyPath = (MotionKeyPosition) key;
                    insertKey(new MotionPaths(parentWidth, parentHeight, keyPath, this.mStartMotionPath, this.mEndMotionPath));
                    if (keyPath.mCurveFit != -1) {
                        this.mCurveFitType = keyPath.mCurveFit;
                    }
                } else if (key instanceof MotionKeyCycle) {
                    key.getAttributeNames(cycleAttributes4);
                } else if (key instanceof MotionKeyTimeCycle) {
                    key.getAttributeNames(timeCycleAttributes4);
                } else if (key instanceof MotionKeyTrigger) {
                    if (triggerList == null) {
                        triggerList = new ArrayList<>();
                    }
                    triggerList.add((MotionKeyTrigger) key);
                } else {
                    key.setInterpolation(interpolation2);
                    key.getAttributeNames(splineAttributes);
                }
            }
        }
        if (triggerList != null) {
            this.mKeyTriggers = (MotionKeyTrigger[]) triggerList.toArray(new MotionKeyTrigger[0]);
        }
        if (splineAttributes.isEmpty()) {
            timeCycleAttributes = timeCycleAttributes4;
            cycleAttributes = cycleAttributes4;
            r18 = 1;
        } else {
            this.mAttributesMap = new HashMap<>();
            Iterator<String> it4 = splineAttributes.iterator();
            while (it4.hasNext()) {
                String attribute2 = it4.next();
                if (attribute2.startsWith("CUSTOM,")) {
                    KeyFrameArray.CustomVar attrList2 = new KeyFrameArray.CustomVar();
                    String customAttributeName = attribute2.split(",")[1];
                    Iterator<MotionKey> it5 = this.mKeyList.iterator();
                    while (it5.hasNext()) {
                        MotionKey key2 = it5.next();
                        HashSet<String> springAttributes3 = springAttributes2;
                        if (key2.mCustom == null) {
                            springAttributes2 = springAttributes3;
                        } else {
                            CustomVariable customAttribute = key2.mCustom.get(customAttributeName);
                            if (customAttribute == null) {
                                timeCycleAttributes3 = timeCycleAttributes4;
                                cycleAttributes3 = cycleAttributes4;
                                attrList = attrList2;
                            } else {
                                timeCycleAttributes3 = timeCycleAttributes4;
                                cycleAttributes3 = cycleAttributes4;
                                attrList = attrList2;
                                attrList.append(key2.mFramePosition, customAttribute);
                            }
                            attrList2 = attrList;
                            springAttributes2 = springAttributes3;
                            timeCycleAttributes4 = timeCycleAttributes3;
                            cycleAttributes4 = cycleAttributes3;
                        }
                    }
                    springAttributes = springAttributes2;
                    timeCycleAttributes2 = timeCycleAttributes4;
                    cycleAttributes2 = cycleAttributes4;
                    splineSets2 = SplineSet.makeCustomSplineSet(attribute2, attrList2);
                } else {
                    springAttributes = springAttributes2;
                    timeCycleAttributes2 = timeCycleAttributes4;
                    cycleAttributes2 = cycleAttributes4;
                    splineSets2 = SplineSet.makeSpline(attribute2, currentTime);
                }
                if (splineSets2 == null) {
                    springAttributes2 = springAttributes;
                    timeCycleAttributes4 = timeCycleAttributes2;
                    cycleAttributes4 = cycleAttributes2;
                } else {
                    splineSets2.setType(attribute2);
                    this.mAttributesMap.put(attribute2, splineSets2);
                    springAttributes2 = springAttributes;
                    timeCycleAttributes4 = timeCycleAttributes2;
                    cycleAttributes4 = cycleAttributes2;
                }
            }
            timeCycleAttributes = timeCycleAttributes4;
            cycleAttributes = cycleAttributes4;
            r18 = 1;
            if (this.mKeyList != null) {
                Iterator<MotionKey> it6 = this.mKeyList.iterator();
                while (it6.hasNext()) {
                    MotionKey key3 = it6.next();
                    if (key3 instanceof MotionKeyAttributes) {
                        key3.addValues(this.mAttributesMap);
                    }
                }
            }
            this.mStartPoint.addValues(this.mAttributesMap, 0);
            this.mEndPoint.addValues(this.mAttributesMap, 100);
            for (String spline : this.mAttributesMap.keySet()) {
                int curve = 0;
                if (interpolation2.containsKey(spline) && (boxedCurve = interpolation2.get(spline)) != null) {
                    curve = boxedCurve.intValue();
                }
                SplineSet splineSet = this.mAttributesMap.get(spline);
                if (splineSet != null) {
                    splineSet.setup(curve);
                }
            }
        }
        if (!timeCycleAttributes.isEmpty()) {
            if (this.mTimeCycleAttributesMap == null) {
                this.mTimeCycleAttributesMap = new HashMap<>();
            }
            Iterator<String> it7 = timeCycleAttributes.iterator();
            while (it7.hasNext()) {
                String attribute3 = it7.next();
                if (!this.mTimeCycleAttributesMap.containsKey(attribute3)) {
                    if (attribute3.startsWith("CUSTOM,")) {
                        KeyFrameArray.CustomVar attrList3 = new KeyFrameArray.CustomVar();
                        String customAttributeName2 = attribute3.split(",")[r18];
                        Iterator<MotionKey> it8 = this.mKeyList.iterator();
                        while (it8.hasNext()) {
                            MotionKey key4 = it8.next();
                            if (key4.mCustom != null) {
                                CustomVariable customAttribute2 = key4.mCustom.get(customAttributeName2);
                                if (customAttribute2 == null) {
                                    it2 = it7;
                                } else {
                                    it2 = it7;
                                    attrList3.append(key4.mFramePosition, customAttribute2);
                                }
                                it7 = it2;
                            }
                        }
                        it = it7;
                        splineSets = SplineSet.makeCustomSplineSet(attribute3, attrList3);
                    } else {
                        it = it7;
                        splineSets = SplineSet.makeSpline(attribute3, currentTime);
                    }
                    if (splineSets == null) {
                        it7 = it;
                    } else {
                        splineSets.setType(attribute3);
                        it7 = it;
                    }
                }
            }
            if (this.mKeyList != null) {
                Iterator<MotionKey> it9 = this.mKeyList.iterator();
                while (it9.hasNext()) {
                    MotionKey key5 = it9.next();
                    if (key5 instanceof MotionKeyTimeCycle) {
                        ((MotionKeyTimeCycle) key5).addTimeValues(this.mTimeCycleAttributesMap);
                    }
                }
            }
            for (String spline2 : this.mTimeCycleAttributesMap.keySet()) {
                int curve2 = 0;
                if (interpolation2.containsKey(spline2)) {
                    curve2 = interpolation2.get(spline2).intValue();
                }
                this.mTimeCycleAttributesMap.get(spline2).setup(curve2);
            }
        }
        MotionPaths[] points = new MotionPaths[this.mMotionPaths.size() + 2];
        int count = 1;
        points[0] = this.mStartMotionPath;
        points[points.length - 1] = this.mEndMotionPath;
        if (this.mMotionPaths.size() > 0 && this.mCurveFitType == MotionKey.UNSET) {
            this.mCurveFitType = 0;
        }
        Iterator<MotionPaths> it10 = this.mMotionPaths.iterator();
        while (it10.hasNext()) {
            MotionPaths point = it10.next();
            points[count] = point;
            count++;
        }
        HashSet<String> attributeNameSet = new HashSet<>();
        for (String s : this.mEndMotionPath.mCustomAttributes.keySet()) {
            if (this.mStartMotionPath.mCustomAttributes.containsKey(s) && !splineAttributes.contains("CUSTOM," + s)) {
                attributeNameSet.add(s);
            }
        }
        this.mAttributeNames = (String[]) attributeNameSet.toArray(new String[0]);
        this.mAttributeInterpolatorCount = new int[this.mAttributeNames.length];
        for (int i = 0; i < this.mAttributeNames.length; i++) {
            String attributeName = this.mAttributeNames[i];
            this.mAttributeInterpolatorCount[i] = 0;
            int j3 = 0;
            while (true) {
                if (j3 >= points.length) {
                    break;
                }
                if (!points[j3].mCustomAttributes.containsKey(attributeName) || (attribute = points[j3].mCustomAttributes.get(attributeName)) == null) {
                    j3++;
                } else {
                    int[] iArr = this.mAttributeInterpolatorCount;
                    iArr[i] = iArr[i] + attribute.numberOfInterpolatedValues();
                    break;
                }
            }
        }
        boolean arcMode = points[0].mPathMotionArc != -1 ? r18 : false;
        boolean[] mask = new boolean[this.mAttributeNames.length + 18];
        for (int i2 = 1; i2 < points.length; i2++) {
            points[i2].different(points[i2 - 1], mask, this.mAttributeNames, arcMode);
        }
        int count2 = 0;
        for (int i3 = 1; i3 < mask.length; i3++) {
            if (mask[i3]) {
                count2++;
            }
        }
        this.mInterpolateVariables = new int[count2];
        int varLen = Math.max(2, count2);
        this.mInterpolateData = new double[varLen];
        this.mInterpolateVelocity = new double[varLen];
        int count3 = 0;
        for (int i4 = 1; i4 < mask.length; i4++) {
            if (mask[i4]) {
                this.mInterpolateVariables[count3] = i4;
                count3++;
            }
        }
        int i5 = points.length;
        int[] iArr2 = new int[2];
        iArr2[r18] = this.mInterpolateVariables.length;
        iArr2[0] = i5;
        double[][] splineData = (double[][]) Array.newInstance((Class<?>) Double.TYPE, iArr2);
        double[] timePoint = new double[points.length];
        int i6 = 0;
        while (i6 < points.length) {
            points[i6].fillStandard(splineData[i6], this.mInterpolateVariables);
            timePoint[i6] = points[i6].mTime;
            i6++;
            count3 = count3;
        }
        int j4 = 0;
        while (j4 < this.mInterpolateVariables.length) {
            int interpolateVariable = this.mInterpolateVariables[j4];
            if (interpolateVariable < MotionPaths.sNames.length) {
                j2 = j4;
                String s2 = MotionPaths.sNames[this.mInterpolateVariables[j2]] + " [";
                int i7 = 0;
                while (i7 < points.length) {
                    s2 = s2 + splineData[i7][j2];
                    i7++;
                    splineAttributes = splineAttributes;
                }
            } else {
                j2 = j4;
            }
            j4 = j2 + 1;
            splineAttributes = splineAttributes;
        }
        this.mSpline = new CurveFit[this.mAttributeNames.length + 1];
        int i8 = 0;
        while (i8 < this.mAttributeNames.length) {
            int pointCount = 0;
            double[][] splinePoints = null;
            double[] timePoints = null;
            String name = this.mAttributeNames[i8];
            int i9 = i8;
            int j5 = 0;
            while (true) {
                interpolation = interpolation2;
                if (j5 < points.length) {
                    if (!points[j5].hasCustomData(name)) {
                        j = j5;
                    } else {
                        if (splinePoints != null) {
                            j = j5;
                        } else {
                            timePoints = new double[points.length];
                            int length = points.length;
                            j = j5;
                            int[] iArr3 = new int[2];
                            iArr3[r18] = points[j].getCustomDataCount(name);
                            iArr3[0] = length;
                            splinePoints = (double[][]) Array.newInstance((Class<?>) Double.TYPE, iArr3);
                        }
                        double[][] splinePoints2 = splinePoints;
                        timePoints[pointCount] = points[j].mTime;
                        points[j].getCustomData(name, splinePoints2[pointCount], 0);
                        pointCount++;
                        splinePoints = splinePoints2;
                    }
                    j5 = j + 1;
                    interpolation2 = interpolation;
                }
            }
            double[] timePoints2 = Arrays.copyOf(timePoints, pointCount);
            double[][] splinePoints3 = (double[][]) Arrays.copyOf(splinePoints, pointCount);
            int pointCount2 = this.mCurveFitType;
            this.mSpline[i9 + 1] = CurveFit.get(pointCount2, timePoints2, splinePoints3);
            i8 = i9 + 1;
            interpolation2 = interpolation;
        }
        this.mSpline[0] = CurveFit.get(this.mCurveFitType, timePoint, splineData);
        if (points[0].mPathMotionArc != -1) {
            int size = points.length;
            int[] mode = new int[size];
            double[] time = new double[size];
            int[] iArr4 = new int[2];
            iArr4[r18] = 2;
            iArr4[0] = size;
            double[][] values = (double[][]) Array.newInstance((Class<?>) Double.TYPE, iArr4);
            int i10 = 0;
            while (i10 < size) {
                mode[i10] = points[i10].mPathMotionArc;
                time[i10] = points[i10].mTime;
                values[i10][0] = points[i10].mX;
                values[i10][r18] = points[i10].mY;
                i10++;
                splineData = splineData;
                timePoint = timePoint;
            }
            this.mArcSpline = CurveFit.getArc(mode, time, values);
        }
        float distance = Float.NaN;
        this.mCycleMap = new HashMap<>();
        if (this.mKeyList != null) {
            Iterator<String> it11 = cycleAttributes.iterator();
            while (it11.hasNext()) {
                String attribute4 = it11.next();
                KeyCycleOscillator cycle = KeyCycleOscillator.makeWidgetCycle(attribute4);
                if (cycle != null) {
                    if (cycle.variesByPath() && Float.isNaN(distance)) {
                        distance = getPreCycleDistance();
                    }
                    cycle.setType(attribute4);
                    this.mCycleMap.put(attribute4, cycle);
                }
            }
            Iterator<MotionKey> it12 = this.mKeyList.iterator();
            while (it12.hasNext()) {
                MotionKey key6 = it12.next();
                if (key6 instanceof MotionKeyCycle) {
                    ((MotionKeyCycle) key6).addCycleValues(this.mCycleMap);
                }
            }
            Iterator<KeyCycleOscillator> it13 = this.mCycleMap.values().iterator();
            while (it13.hasNext()) {
                it13.next().setup(distance);
            }
        }
    }

    public String toString() {
        return " start: x: " + this.mStartMotionPath.mX + " y: " + this.mStartMotionPath.mY + " end: x: " + this.mEndMotionPath.mX + " y: " + this.mEndMotionPath.mY;
    }

    private void readView(MotionPaths motionPaths) {
        motionPaths.setBounds(this.mView.getX(), this.mView.getY(), this.mView.getWidth(), this.mView.getHeight());
    }

    public void setView(MotionWidget view) {
        this.mView = view;
    }

    public MotionWidget getView() {
        return this.mView;
    }

    public void setStart(MotionWidget mw) {
        this.mStartMotionPath.mTime = 0.0f;
        this.mStartMotionPath.mPosition = 0.0f;
        this.mStartMotionPath.setBounds(mw.getX(), mw.getY(), mw.getWidth(), mw.getHeight());
        this.mStartMotionPath.applyParameters(mw);
        this.mStartPoint.setState(mw);
        TypedBundle p = mw.getWidgetFrame().getMotionProperties();
        if (p != null) {
            p.applyDelta(this);
        }
    }

    public void setEnd(MotionWidget mw) {
        this.mEndMotionPath.mTime = 1.0f;
        this.mEndMotionPath.mPosition = 1.0f;
        readView(this.mEndMotionPath);
        this.mEndMotionPath.setBounds(mw.getLeft(), mw.getTop(), mw.getWidth(), mw.getHeight());
        this.mEndMotionPath.applyParameters(mw);
        this.mEndPoint.setState(mw);
    }

    public void setStartState(ViewState rect, MotionWidget v, int rotation, int preWidth, int preHeight) {
        this.mStartMotionPath.mTime = 0.0f;
        this.mStartMotionPath.mPosition = 0.0f;
        Rect r = new Rect();
        switch (rotation) {
            case 1:
                int cx = rect.left;
                int cx2 = cx + rect.right;
                int cy = rect.top + rect.bottom;
                r.left = (cy - rect.width()) / 2;
                r.top = preWidth - ((rect.height() + cx2) / 2);
                r.right = r.left + rect.width();
                r.bottom = r.top + rect.height();
                break;
            case 2:
                int cx3 = rect.left + rect.right;
                int cy2 = rect.top + rect.bottom;
                r.left = preHeight - ((rect.width() + cy2) / 2);
                r.top = (cx3 - rect.height()) / 2;
                r.right = r.left + rect.width();
                r.bottom = r.top + rect.height();
                break;
        }
        this.mStartMotionPath.setBounds(r.left, r.top, r.width(), r.height());
        this.mStartPoint.setState(r, v, rotation, rect.rotation);
    }

    void rotate(Rect rect, Rect out, int rotation, int preHeight, int preWidth) {
        switch (rotation) {
            case 1:
                int cx = rect.left;
                int cx2 = cx + rect.right;
                int cy = rect.top + rect.bottom;
                out.left = (cy - rect.width()) / 2;
                out.top = preWidth - ((rect.height() + cx2) / 2);
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                break;
            case 2:
                int cx3 = rect.left;
                int cx4 = cx3 + rect.right;
                int cy2 = rect.top + rect.bottom;
                out.left = preHeight - ((rect.width() + cy2) / 2);
                out.top = (cx4 - rect.height()) / 2;
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                break;
            case 3:
                int cx5 = rect.left;
                int cx6 = cx5 + rect.right;
                int i = rect.top + rect.bottom;
                out.left = ((rect.height() / 2) + rect.top) - (cx6 / 2);
                out.top = preWidth - ((rect.height() + cx6) / 2);
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                break;
            case 4:
                int cx7 = rect.left + rect.right;
                int cy3 = rect.bottom + rect.top;
                out.left = preHeight - ((rect.width() + cy3) / 2);
                out.top = (cx7 - rect.height()) / 2;
                out.right = out.left + rect.width();
                out.bottom = out.top + rect.height();
                break;
        }
    }

    private static DifferentialInterpolator getInterpolator(int type, String interpolatorString, int id) {
        switch (type) {
            case -1:
                final Easing easing = Easing.getInterpolator(interpolatorString);
                return new DifferentialInterpolator() { // from class: androidx.constraintlayout.core.motion.Motion.1
                    float mX;

                    @Override // androidx.constraintlayout.core.motion.utils.DifferentialInterpolator
                    public float getInterpolation(float x) {
                        this.mX = x;
                        return (float) easing.get(x);
                    }

                    @Override // androidx.constraintlayout.core.motion.utils.DifferentialInterpolator
                    public float getVelocity() {
                        return (float) easing.getDiff(this.mX);
                    }
                };
            default:
                return null;
        }
    }

    void setBothStates(MotionWidget v) {
        this.mStartMotionPath.mTime = 0.0f;
        this.mStartMotionPath.mPosition = 0.0f;
        this.mNoMovement = true;
        this.mStartMotionPath.setBounds(v.getX(), v.getY(), v.getWidth(), v.getHeight());
        this.mEndMotionPath.setBounds(v.getX(), v.getY(), v.getWidth(), v.getHeight());
        this.mStartPoint.setState(v);
        this.mEndPoint.setState(v);
    }

    private float getAdjustedPosition(float position, float[] velocity) {
        if (velocity != null) {
            velocity[0] = 1.0f;
        } else if (this.mStaggerScale != 1.0d) {
            if (position < this.mStaggerOffset) {
                position = 0.0f;
            }
            if (position > this.mStaggerOffset && position < 1.0d) {
                position = Math.min((position - this.mStaggerOffset) * this.mStaggerScale, 1.0f);
            }
        }
        float adjusted = position;
        Easing easing = this.mStartMotionPath.mKeyFrameEasing;
        float start = 0.0f;
        float end = Float.NaN;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths frame = it.next();
            if (frame.mKeyFrameEasing != null) {
                if (frame.mTime < position) {
                    easing = frame.mKeyFrameEasing;
                    start = frame.mTime;
                } else if (Float.isNaN(end)) {
                    end = frame.mTime;
                }
            }
        }
        if (easing != null) {
            if (Float.isNaN(end)) {
                end = 1.0f;
            }
            float offset = (position - start) / (end - start);
            float new_offset = (float) easing.get(offset);
            adjusted = ((end - start) * new_offset) + start;
            if (velocity != null) {
                velocity[0] = (float) easing.getDiff(offset);
            }
        }
        return adjusted;
    }

    void endTrigger(boolean start) {
    }

    public boolean interpolate(MotionWidget child, float globalPosition, long time, KeyCache keyCache) {
        float pin;
        float section;
        MotionWidget motionWidget = child;
        float position = getAdjustedPosition(globalPosition, null);
        if (this.mQuantizeMotionSteps == -1) {
            pin = position;
        } else {
            float steps = 1.0f / this.mQuantizeMotionSteps;
            float jump = ((float) Math.floor(position / steps)) * steps;
            float section2 = (position % steps) / steps;
            if (!Float.isNaN(this.mQuantizeMotionPhase)) {
                section2 = (this.mQuantizeMotionPhase + section2) % 1.0f;
            }
            if (this.mQuantizeMotionInterpolator != null) {
                section = this.mQuantizeMotionInterpolator.getInterpolation(section2);
            } else {
                section = ((double) section2) > 0.5d ? 1.0f : 0.0f;
            }
            pin = (section * steps) + jump;
        }
        if (this.mAttributesMap != null) {
            for (SplineSet aSpline : this.mAttributesMap.values()) {
                aSpline.setProperty(motionWidget, pin);
            }
        }
        if (this.mSpline != null) {
            this.mSpline[0].getPos(pin, this.mInterpolateData);
            this.mSpline[0].getSlope(pin, this.mInterpolateVelocity);
            if (this.mArcSpline != null && this.mInterpolateData.length > 0) {
                this.mArcSpline.getPos(pin, this.mInterpolateData);
                this.mArcSpline.getSlope(pin, this.mInterpolateVelocity);
            }
            if (!this.mNoMovement) {
                float position2 = pin;
                this.mStartMotionPath.setView(position2, motionWidget, this.mInterpolateVariables, this.mInterpolateData, this.mInterpolateVelocity, null);
                pin = position2;
                motionWidget = motionWidget;
            }
            if (this.mTransformPivotTarget != -1) {
                if (this.mTransformPivotView == null) {
                    MotionWidget layout = motionWidget.getParent();
                    this.mTransformPivotView = layout.findViewById(this.mTransformPivotTarget);
                }
                MotionWidget layout2 = this.mTransformPivotView;
                if (layout2 != null) {
                    float cy = (this.mTransformPivotView.getTop() + this.mTransformPivotView.getBottom()) / 2.0f;
                    float cx = (this.mTransformPivotView.getLeft() + this.mTransformPivotView.getRight()) / 2.0f;
                    if (motionWidget.getRight() - motionWidget.getLeft() > 0 && motionWidget.getBottom() - motionWidget.getTop() > 0) {
                        float px = cx - motionWidget.getLeft();
                        float py = cy - motionWidget.getTop();
                        motionWidget.setPivotX(px);
                        motionWidget.setPivotY(py);
                    }
                }
            }
            for (int i = 1; i < this.mSpline.length; i++) {
                CurveFit spline = this.mSpline[i];
                spline.getPos(pin, this.mValuesBuff);
                this.mStartMotionPath.mCustomAttributes.get(this.mAttributeNames[i - 1]).setInterpolatedValue(motionWidget, this.mValuesBuff);
            }
            if (this.mStartPoint.mVisibilityMode == 0) {
                if (pin <= 0.0f) {
                    motionWidget.setVisibility(this.mStartPoint.mVisibility);
                } else if (pin < 1.0f) {
                    if (this.mEndPoint.mVisibility != this.mStartPoint.mVisibility) {
                        motionWidget.setVisibility(4);
                    }
                } else {
                    motionWidget.setVisibility(this.mEndPoint.mVisibility);
                }
            }
            if (this.mKeyTriggers != null) {
                for (int i2 = 0; i2 < this.mKeyTriggers.length; i2++) {
                    this.mKeyTriggers[i2].conditionallyFire(pin, motionWidget);
                }
            }
        } else {
            float float_l = this.mStartMotionPath.mX + ((this.mEndMotionPath.mX - this.mStartMotionPath.mX) * pin);
            float float_t = this.mStartMotionPath.mY + ((this.mEndMotionPath.mY - this.mStartMotionPath.mY) * pin);
            float float_width = this.mStartMotionPath.mWidth + ((this.mEndMotionPath.mWidth - this.mStartMotionPath.mWidth) * pin);
            float float_height = this.mStartMotionPath.mHeight + ((this.mEndMotionPath.mHeight - this.mStartMotionPath.mHeight) * pin);
            int l = (int) (float_l + 0.5f);
            int t = (int) (float_t + 0.5f);
            int r = (int) (float_l + 0.5f + float_width);
            int b = (int) (0.5f + float_t + float_height);
            int i3 = r - l;
            int i4 = b - t;
            motionWidget.layout(l, t, r, b);
        }
        if (this.mCycleMap != null) {
            for (KeyCycleOscillator osc : this.mCycleMap.values()) {
                if (osc instanceof KeyCycleOscillator.PathRotateSet) {
                    ((KeyCycleOscillator.PathRotateSet) osc).setPathRotate(motionWidget, pin, this.mInterpolateVelocity[0], this.mInterpolateVelocity[1]);
                } else {
                    osc.setProperty(motionWidget, pin);
                }
            }
        }
        return false;
    }

    public void getDpDt(float position, float locationX, float locationY, float[] mAnchorDpDt) {
        float position2 = getAdjustedPosition(position, this.mVelocity);
        if (this.mSpline != null) {
            this.mSpline[0].getSlope(position2, this.mInterpolateVelocity);
            this.mSpline[0].getPos(position2, this.mInterpolateData);
            float v = this.mVelocity[0];
            for (int i = 0; i < this.mInterpolateVelocity.length; i++) {
                double[] dArr = this.mInterpolateVelocity;
                dArr[i] = dArr[i] * v;
            }
            if (this.mArcSpline == null) {
                this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
                return;
            } else {
                if (this.mInterpolateData.length > 0) {
                    this.mArcSpline.getPos(position2, this.mInterpolateData);
                    this.mArcSpline.getSlope(position2, this.mInterpolateVelocity);
                    this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
                    return;
                }
                return;
            }
        }
        float dleft = this.mEndMotionPath.mX - this.mStartMotionPath.mX;
        float dTop = this.mEndMotionPath.mY - this.mStartMotionPath.mY;
        float dWidth = this.mEndMotionPath.mWidth - this.mStartMotionPath.mWidth;
        float dHeight = this.mEndMotionPath.mHeight - this.mStartMotionPath.mHeight;
        float dRight = dleft + dWidth;
        float dBottom = dTop + dHeight;
        mAnchorDpDt[0] = ((1.0f - locationX) * dleft) + (dRight * locationX);
        mAnchorDpDt[1] = ((1.0f - locationY) * dTop) + (dBottom * locationY);
    }

    void getPostLayoutDvDp(float position, int width, int height, float locationX, float locationY, float[] mAnchorDpDt) {
        VelocityMatrix vmat;
        float position2 = getAdjustedPosition(position, this.mVelocity);
        SplineSet trans_x = this.mAttributesMap == null ? null : this.mAttributesMap.get("translationX");
        SplineSet trans_y = this.mAttributesMap == null ? null : this.mAttributesMap.get("translationY");
        SplineSet rotation = this.mAttributesMap == null ? null : this.mAttributesMap.get("rotationZ");
        SplineSet scale_x = this.mAttributesMap == null ? null : this.mAttributesMap.get("scaleX");
        SplineSet scale_y = this.mAttributesMap == null ? null : this.mAttributesMap.get("scaleY");
        KeyCycleOscillator osc_x = this.mCycleMap == null ? null : this.mCycleMap.get("translationX");
        KeyCycleOscillator osc_y = this.mCycleMap == null ? null : this.mCycleMap.get("translationY");
        KeyCycleOscillator osc_r = this.mCycleMap == null ? null : this.mCycleMap.get("rotationZ");
        KeyCycleOscillator osc_sx = this.mCycleMap == null ? null : this.mCycleMap.get("scaleX");
        KeyCycleOscillator osc_sy = this.mCycleMap != null ? this.mCycleMap.get("scaleY") : null;
        VelocityMatrix vmat2 = new VelocityMatrix();
        vmat2.clear();
        vmat2.setRotationVelocity(rotation, position2);
        vmat2.setTranslationVelocity(trans_x, trans_y, position2);
        vmat2.setScaleVelocity(scale_x, scale_y, position2);
        vmat2.setRotationVelocity(osc_r, position2);
        vmat2.setTranslationVelocity(osc_x, osc_y, position2);
        vmat2.setScaleVelocity(osc_sx, osc_sy, position2);
        if (this.mArcSpline != null) {
            if (this.mInterpolateData.length > 0) {
                vmat = vmat2;
                this.mArcSpline.getPos(position2, this.mInterpolateData);
                this.mArcSpline.getSlope(position2, this.mInterpolateVelocity);
                this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
            } else {
                vmat = vmat2;
            }
            vmat.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
            return;
        }
        if (this.mSpline != null) {
            float position3 = getAdjustedPosition(position2, this.mVelocity);
            this.mSpline[0].getSlope(position3, this.mInterpolateVelocity);
            this.mSpline[0].getPos(position3, this.mInterpolateData);
            float v = this.mVelocity[0];
            int i = 0;
            while (i < this.mInterpolateVelocity.length) {
                double[] dArr = this.mInterpolateVelocity;
                int i2 = i;
                dArr[i2] = dArr[i] * v;
                i = i2 + 1;
            }
            this.mStartMotionPath.setDpDt(locationX, locationY, mAnchorDpDt, this.mInterpolateVariables, this.mInterpolateVelocity, this.mInterpolateData);
            vmat2.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
            return;
        }
        float dleft = this.mEndMotionPath.mX - this.mStartMotionPath.mX;
        float dTop = this.mEndMotionPath.mY - this.mStartMotionPath.mY;
        float dWidth = this.mEndMotionPath.mWidth - this.mStartMotionPath.mWidth;
        float dHeight = this.mEndMotionPath.mHeight - this.mStartMotionPath.mHeight;
        float dRight = dleft + dWidth;
        float dBottom = dTop + dHeight;
        mAnchorDpDt[0] = ((1.0f - locationX) * dleft) + (dRight * locationX);
        mAnchorDpDt[1] = ((1.0f - locationY) * dTop) + (dBottom * locationY);
        vmat2.clear();
        vmat2.setRotationVelocity(rotation, position2);
        vmat2.setTranslationVelocity(trans_x, trans_y, position2);
        vmat2.setScaleVelocity(scale_x, scale_y, position2);
        vmat2.setRotationVelocity(osc_r, position2);
        vmat2.setTranslationVelocity(osc_x, osc_y, position2);
        vmat2.setScaleVelocity(osc_sx, osc_sy, position2);
        vmat2.applyTransform(locationX, locationY, width, height, mAnchorDpDt);
    }

    public int getDrawPath() {
        int mode = this.mStartMotionPath.mDrawPath;
        Iterator<MotionPaths> it = this.mMotionPaths.iterator();
        while (it.hasNext()) {
            MotionPaths keyFrame = it.next();
            mode = Math.max(mode, keyFrame.mDrawPath);
        }
        return Math.max(mode, this.mEndMotionPath.mDrawPath);
    }

    public void setDrawPath(int debugMode) {
        this.mStartMotionPath.mDrawPath = debugMode;
    }

    String name() {
        return this.mView.getName();
    }

    void positionKeyframe(MotionWidget view, MotionKeyPosition key, float x, float y, String[] attribute, float[] value) {
        FloatRect start = new FloatRect();
        start.left = this.mStartMotionPath.mX;
        start.top = this.mStartMotionPath.mY;
        start.right = start.left + this.mStartMotionPath.mWidth;
        start.bottom = start.top + this.mStartMotionPath.mHeight;
        FloatRect end = new FloatRect();
        end.left = this.mEndMotionPath.mX;
        end.top = this.mEndMotionPath.mY;
        end.right = end.left + this.mEndMotionPath.mWidth;
        end.bottom = end.top + this.mEndMotionPath.mHeight;
        key.positionAttributes(view, start, end, x, y, attribute, value);
    }

    public int getKeyFramePositions(int[] type, float[] pos) {
        int i = 0;
        Iterator<MotionKey> it = this.mKeyList.iterator();
        int count = 0;
        while (it.hasNext()) {
            MotionKey key = it.next();
            int i2 = i + 1;
            type[i] = key.mFramePosition + (key.mType * 1000);
            float time = key.mFramePosition / 100.0f;
            this.mSpline[0].getPos(time, this.mInterpolateData);
            this.mStartMotionPath.getCenter(time, this.mInterpolateVariables, this.mInterpolateData, pos, count);
            count += 2;
            i = i2;
        }
        return i;
    }

    public int getKeyFrameInfo(int type, int[] info) {
        int count = 0;
        int cursor = 0;
        float[] pos = new float[2];
        Iterator<MotionKey> it = this.mKeyList.iterator();
        while (it.hasNext()) {
            MotionKey key = it.next();
            if (key.mType == type || type != -1) {
                int len = cursor;
                info[cursor] = 0;
                int cursor2 = cursor + 1;
                info[cursor2] = key.mType;
                int cursor3 = cursor2 + 1;
                info[cursor3] = key.mFramePosition;
                float time = key.mFramePosition / 100.0f;
                this.mSpline[0].getPos(time, this.mInterpolateData);
                this.mStartMotionPath.getCenter(time, this.mInterpolateVariables, this.mInterpolateData, pos, 0);
                int cursor4 = cursor3 + 1;
                info[cursor4] = Float.floatToIntBits(pos[0]);
                int cursor5 = cursor4 + 1;
                info[cursor5] = Float.floatToIntBits(pos[1]);
                if (key instanceof MotionKeyPosition) {
                    MotionKeyPosition kp = (MotionKeyPosition) key;
                    int cursor6 = cursor5 + 1;
                    info[cursor6] = kp.mPositionType;
                    int cursor7 = cursor6 + 1;
                    info[cursor7] = Float.floatToIntBits(kp.mPercentX);
                    cursor5 = cursor7 + 1;
                    info[cursor5] = Float.floatToIntBits(kp.mPercentY);
                }
                cursor = cursor5 + 1;
                info[len] = cursor - len;
                count++;
            }
        }
        return count;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, int value) {
        switch (id) {
            case 509:
                setPathMotionArc(value);
                break;
            case TypedValues.MotionType.TYPE_QUANTIZE_MOTIONSTEPS /* 610 */:
                this.mQuantizeMotionSteps = value;
                break;
            case TypedValues.TransitionType.TYPE_AUTO_TRANSITION /* 704 */:
                break;
        }
        return true;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, float value) {
        if (602 == id) {
            this.mQuantizeMotionPhase = value;
            return true;
        }
        if (600 == id) {
            this.mMotionStagger = value;
            return true;
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, String value) {
        if (705 == id || 611 == id) {
            this.mQuantizeMotionInterpolator = getInterpolator(-1, value, 0);
            return true;
        }
        if (605 != id) {
            return false;
        }
        this.mStartMotionPath.mAnimateRelativeTo = value;
        return true;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public boolean setValue(int id, boolean value) {
        return false;
    }

    @Override // androidx.constraintlayout.core.motion.utils.TypedValues
    public int getId(String name) {
        return 0;
    }

    public void setStaggerScale(float staggerScale) {
        this.mStaggerScale = staggerScale;
    }

    public void setStaggerOffset(float staggerOffset) {
        this.mStaggerOffset = staggerOffset;
    }

    public float getMotionStagger() {
        return this.mMotionStagger;
    }

    public void setIdString(String stringId) {
        this.mId = stringId;
        this.mStartMotionPath.mId = this.mId;
    }
}
