package androidx.constraintlayout.core.state;

import androidx.constraintlayout.core.motion.CustomAttribute;
import androidx.constraintlayout.core.motion.CustomVariable;
import androidx.constraintlayout.core.motion.utils.TypedBundle;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.parser.CLElement;
import androidx.constraintlayout.core.parser.CLKey;
import androidx.constraintlayout.core.parser.CLNumber;
import androidx.constraintlayout.core.parser.CLObject;
import androidx.constraintlayout.core.parser.CLParsingException;
import androidx.constraintlayout.core.state.Transition;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.core.os.EnvironmentCompat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes.dex */
public class WidgetFrame {
    public static float phone_orientation = Float.NaN;
    public float alpha;
    public int bottom;
    public float interpolatedPos;
    public int left;
    private final HashMap<String, CustomVariable> mCustom;
    TypedBundle mMotionProperties;
    public String name;
    public float pivotX;
    public float pivotY;
    public int right;
    public float rotationX;
    public float rotationY;
    public float rotationZ;
    public float scaleX;
    public float scaleY;
    public int top;
    public float translationX;
    public float translationY;
    public float translationZ;
    public int visibility;
    public ConstraintWidget widget;

    public int width() {
        return Math.max(0, this.right - this.left);
    }

    public int height() {
        return Math.max(0, this.bottom - this.top);
    }

    public WidgetFrame() {
        this.widget = null;
        this.left = 0;
        this.top = 0;
        this.right = 0;
        this.bottom = 0;
        this.pivotX = Float.NaN;
        this.pivotY = Float.NaN;
        this.rotationX = Float.NaN;
        this.rotationY = Float.NaN;
        this.rotationZ = Float.NaN;
        this.translationX = Float.NaN;
        this.translationY = Float.NaN;
        this.translationZ = Float.NaN;
        this.scaleX = Float.NaN;
        this.scaleY = Float.NaN;
        this.alpha = Float.NaN;
        this.interpolatedPos = Float.NaN;
        this.visibility = 0;
        this.mCustom = new HashMap<>();
        this.name = null;
    }

    public WidgetFrame(ConstraintWidget widget) {
        this.widget = null;
        this.left = 0;
        this.top = 0;
        this.right = 0;
        this.bottom = 0;
        this.pivotX = Float.NaN;
        this.pivotY = Float.NaN;
        this.rotationX = Float.NaN;
        this.rotationY = Float.NaN;
        this.rotationZ = Float.NaN;
        this.translationX = Float.NaN;
        this.translationY = Float.NaN;
        this.translationZ = Float.NaN;
        this.scaleX = Float.NaN;
        this.scaleY = Float.NaN;
        this.alpha = Float.NaN;
        this.interpolatedPos = Float.NaN;
        this.visibility = 0;
        this.mCustom = new HashMap<>();
        this.name = null;
        this.widget = widget;
    }

    public WidgetFrame(WidgetFrame frame) {
        this.widget = null;
        this.left = 0;
        this.top = 0;
        this.right = 0;
        this.bottom = 0;
        this.pivotX = Float.NaN;
        this.pivotY = Float.NaN;
        this.rotationX = Float.NaN;
        this.rotationY = Float.NaN;
        this.rotationZ = Float.NaN;
        this.translationX = Float.NaN;
        this.translationY = Float.NaN;
        this.translationZ = Float.NaN;
        this.scaleX = Float.NaN;
        this.scaleY = Float.NaN;
        this.alpha = Float.NaN;
        this.interpolatedPos = Float.NaN;
        this.visibility = 0;
        this.mCustom = new HashMap<>();
        this.name = null;
        this.widget = frame.widget;
        this.left = frame.left;
        this.top = frame.top;
        this.right = frame.right;
        this.bottom = frame.bottom;
        updateAttributes(frame);
    }

    public void updateAttributes(WidgetFrame frame) {
        if (frame == null) {
            return;
        }
        this.pivotX = frame.pivotX;
        this.pivotY = frame.pivotY;
        this.rotationX = frame.rotationX;
        this.rotationY = frame.rotationY;
        this.rotationZ = frame.rotationZ;
        this.translationX = frame.translationX;
        this.translationY = frame.translationY;
        this.translationZ = frame.translationZ;
        this.scaleX = frame.scaleX;
        this.scaleY = frame.scaleY;
        this.alpha = frame.alpha;
        this.visibility = frame.visibility;
        setMotionAttributes(frame.mMotionProperties);
        this.mCustom.clear();
        for (CustomVariable c : frame.mCustom.values()) {
            this.mCustom.put(c.getName(), c.copy());
        }
    }

    public boolean isDefaultTransform() {
        return Float.isNaN(this.rotationX) && Float.isNaN(this.rotationY) && Float.isNaN(this.rotationZ) && Float.isNaN(this.translationX) && Float.isNaN(this.translationY) && Float.isNaN(this.translationZ) && Float.isNaN(this.scaleX) && Float.isNaN(this.scaleY) && Float.isNaN(this.alpha);
    }

    public static void interpolate(int parentWidth, int parentHeight, WidgetFrame frame, WidgetFrame start, WidgetFrame end, Transition transition, float progress) {
        float startAlpha;
        int startY;
        int endHeight;
        float endAlpha;
        float startAlpha2;
        float startAlpha3;
        float endAlpha2;
        int interpolateStartFrame;
        int endX;
        int endY;
        int startY2;
        Iterator<String> it;
        int startX;
        int startY3;
        WidgetFrame widgetFrame = frame;
        WidgetFrame widgetFrame2 = start;
        WidgetFrame widgetFrame3 = end;
        int frameNumber = (int) (progress * 100.0f);
        int startX2 = widgetFrame2.left;
        int startY4 = widgetFrame2.top;
        int endX2 = widgetFrame3.left;
        int endY2 = widgetFrame3.top;
        int startWidth = widgetFrame2.right - widgetFrame2.left;
        int startHeight = widgetFrame2.bottom - widgetFrame2.top;
        int endWidth = widgetFrame3.right - widgetFrame3.left;
        int endHeight2 = widgetFrame3.bottom - widgetFrame3.top;
        float progressPosition = progress;
        int startX3 = startX2;
        float startAlpha4 = widgetFrame2.alpha;
        float startAlpha5 = widgetFrame3.alpha;
        if (widgetFrame2.visibility != 8) {
            startAlpha = startAlpha4;
            startY = startY4;
        } else {
            int startX4 = startX3 - ((int) (endWidth / 2.0f));
            startY = startY4 - ((int) (endHeight2 / 2.0f));
            startWidth = endWidth;
            startHeight = endHeight2;
            if (!Float.isNaN(startAlpha4)) {
                startX3 = startX4;
                startAlpha = startAlpha4;
            } else {
                startX3 = startX4;
                startAlpha = 0.0f;
            }
        }
        float startAlpha6 = startAlpha;
        if (widgetFrame3.visibility != 8) {
            endHeight = endHeight2;
            endAlpha = startAlpha5;
        } else {
            endX2 -= (int) (startWidth / 2.0f);
            endY2 -= (int) (startHeight / 2.0f);
            endWidth = startWidth;
            endHeight = startHeight;
            if (!Float.isNaN(startAlpha5)) {
                endAlpha = startAlpha5;
            } else {
                endAlpha = 0.0f;
            }
        }
        if (Float.isNaN(startAlpha6) && !Float.isNaN(endAlpha)) {
            startAlpha2 = 1.0f;
        } else {
            startAlpha2 = startAlpha6;
        }
        if (!Float.isNaN(startAlpha2) && Float.isNaN(endAlpha)) {
            endAlpha = 1.0f;
        }
        float endAlpha3 = endAlpha;
        int startY5 = startY;
        if (widgetFrame2.visibility != 4) {
            startAlpha3 = startAlpha2;
        } else {
            startAlpha3 = 0.0f;
        }
        int endY3 = endX2;
        if (widgetFrame3.visibility != 4) {
            endAlpha2 = endAlpha3;
        } else {
            endAlpha2 = 0.0f;
        }
        if (widgetFrame.widget != null && transition.hasPositionKeyframes()) {
            Transition.KeyPosition firstPosition = transition.findPreviousPosition(widgetFrame.widget.stringId, frameNumber);
            int endY4 = endY2;
            Transition.KeyPosition lastPosition = transition.findNextPosition(widgetFrame.widget.stringId, frameNumber);
            if (firstPosition == lastPosition) {
                lastPosition = null;
            }
            int interpolateEndFrame = 100;
            if (firstPosition != null) {
                int startX5 = (int) (parentWidth * firstPosition.mX);
                startX3 = startX5;
                startY5 = (int) (parentHeight * firstPosition.mY);
                startY3 = firstPosition.mFrame;
            } else {
                startY3 = 0;
            }
            if (lastPosition != null) {
                int endX3 = (int) (parentWidth * lastPosition.mX);
                int endY5 = (int) (parentHeight * lastPosition.mY);
                interpolateEndFrame = lastPosition.mFrame;
                endY4 = endY5;
                endY3 = endX3;
            }
            progressPosition = ((progress * 100.0f) - startY3) / (interpolateEndFrame - startY3);
            interpolateStartFrame = startX3;
            endX = endY3;
            endY = endY4;
            startY2 = startY5;
        } else {
            interpolateStartFrame = startX3;
            endX = endY3;
            endY = endY2;
            startY2 = startY5;
        }
        widgetFrame.widget = widgetFrame2.widget;
        widgetFrame.left = (int) (interpolateStartFrame + ((endX - interpolateStartFrame) * progressPosition));
        widgetFrame.top = (int) (startY2 + ((endY - startY2) * progressPosition));
        int width = (int) (((1.0f - progress) * startWidth) + (endWidth * progress));
        int height = (int) (((1.0f - progress) * startHeight) + (endHeight * progress));
        widgetFrame.right = widgetFrame.left + width;
        widgetFrame.bottom = widgetFrame.top + height;
        widgetFrame.pivotX = interpolate(widgetFrame2.pivotX, widgetFrame3.pivotX, 0.5f, progress);
        widgetFrame.pivotY = interpolate(widgetFrame2.pivotY, widgetFrame3.pivotY, 0.5f, progress);
        widgetFrame.rotationX = interpolate(widgetFrame2.rotationX, widgetFrame3.rotationX, 0.0f, progress);
        widgetFrame.rotationY = interpolate(widgetFrame2.rotationY, widgetFrame3.rotationY, 0.0f, progress);
        widgetFrame.rotationZ = interpolate(widgetFrame2.rotationZ, widgetFrame3.rotationZ, 0.0f, progress);
        widgetFrame.scaleX = interpolate(widgetFrame2.scaleX, widgetFrame3.scaleX, 1.0f, progress);
        widgetFrame.scaleY = interpolate(widgetFrame2.scaleY, widgetFrame3.scaleY, 1.0f, progress);
        widgetFrame.translationX = interpolate(widgetFrame2.translationX, widgetFrame3.translationX, 0.0f, progress);
        widgetFrame.translationY = interpolate(widgetFrame2.translationY, widgetFrame3.translationY, 0.0f, progress);
        widgetFrame.translationZ = interpolate(widgetFrame2.translationZ, widgetFrame3.translationZ, 0.0f, progress);
        widgetFrame.alpha = interpolate(startAlpha3, endAlpha2, 1.0f, progress);
        Set<String> keys = widgetFrame3.mCustom.keySet();
        widgetFrame.mCustom.clear();
        Iterator<String> it2 = keys.iterator();
        while (it2.hasNext()) {
            String key = it2.next();
            Set<String> keys2 = keys;
            if (!widgetFrame2.mCustom.containsKey(key)) {
                it = it2;
                startX = interpolateStartFrame;
            } else {
                CustomVariable startVariable = widgetFrame2.mCustom.get(key);
                it = it2;
                CustomVariable endVariable = widgetFrame3.mCustom.get(key);
                CustomVariable interpolated = new CustomVariable(startVariable);
                widgetFrame.mCustom.put(key, interpolated);
                if (startVariable.numberOfInterpolatedValues() == 1) {
                    startX = interpolateStartFrame;
                    interpolated.setValue(Float.valueOf(interpolate(startVariable.getValueToInterpolate(), endVariable.getValueToInterpolate(), 0.0f, progress)));
                } else {
                    startX = interpolateStartFrame;
                    int n = startVariable.numberOfInterpolatedValues();
                    float[] startValues = new float[n];
                    float[] endValues = new float[n];
                    startVariable.getValuesToInterpolate(startValues);
                    endVariable.getValuesToInterpolate(endValues);
                    int i = 0;
                    while (i < n) {
                        int i2 = i;
                        startValues[i2] = interpolate(startValues[i2], endValues[i2], 0.0f, progress);
                        interpolated.setValue(startValues);
                        i = i2 + 1;
                        endVariable = endVariable;
                        n = n;
                    }
                }
            }
            widgetFrame = frame;
            widgetFrame2 = start;
            widgetFrame3 = end;
            keys = keys2;
            it2 = it;
            interpolateStartFrame = startX;
        }
    }

    private static float interpolate(float start, float end, float defaultValue, float progress) {
        boolean isStartUnset = Float.isNaN(start);
        boolean isEndUnset = Float.isNaN(end);
        if (isStartUnset && isEndUnset) {
            return Float.NaN;
        }
        if (isStartUnset) {
            start = defaultValue;
        }
        if (isEndUnset) {
            end = defaultValue;
        }
        return ((end - start) * progress) + start;
    }

    public float centerX() {
        return this.left + ((this.right - this.left) / 2.0f);
    }

    public float centerY() {
        return this.top + ((this.bottom - this.top) / 2.0f);
    }

    public WidgetFrame update() {
        if (this.widget != null) {
            this.left = this.widget.getLeft();
            this.top = this.widget.getTop();
            this.right = this.widget.getRight();
            this.bottom = this.widget.getBottom();
            WidgetFrame frame = this.widget.frame;
            updateAttributes(frame);
        }
        return this;
    }

    public WidgetFrame update(ConstraintWidget widget) {
        if (widget == null) {
            return this;
        }
        this.widget = widget;
        update();
        return this;
    }

    public boolean containsCustom(String name) {
        return this.mCustom.containsKey(name);
    }

    public void addCustomColor(String name, int color) {
        setCustomAttribute(name, TypedValues.Custom.TYPE_COLOR, color);
    }

    public int getCustomColor(String name) {
        if (this.mCustom.containsKey(name)) {
            return this.mCustom.get(name).getColorValue();
        }
        return -21880;
    }

    public void addCustomFloat(String name, float value) {
        setCustomAttribute(name, TypedValues.Custom.TYPE_FLOAT, value);
    }

    public float getCustomFloat(String name) {
        if (this.mCustom.containsKey(name)) {
            return this.mCustom.get(name).getFloatValue();
        }
        return Float.NaN;
    }

    public void setCustomAttribute(String name, int type, float value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setFloatValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public void setCustomAttribute(String name, int type, int value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setIntValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public void setCustomAttribute(String name, int type, boolean value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setBooleanValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public void setCustomAttribute(String name, int type, String value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setStringValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public CustomVariable getCustomAttribute(String name) {
        return this.mCustom.get(name);
    }

    public Set<String> getCustomAttributeNames() {
        return this.mCustom.keySet();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00d5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean setValue(java.lang.String r4, androidx.constraintlayout.core.parser.CLElement r5) throws androidx.constraintlayout.core.parser.CLParsingException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 460
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.WidgetFrame.setValue(java.lang.String, androidx.constraintlayout.core.parser.CLElement):boolean");
    }

    public String getId() {
        if (this.widget == null) {
            return EnvironmentCompat.MEDIA_UNKNOWN;
        }
        return this.widget.stringId;
    }

    void parseCustom(CLElement custom) throws CLParsingException, NumberFormatException {
        CLObject obj = (CLObject) custom;
        int n = obj.size();
        for (int i = 0; i < n; i++) {
            CLElement tmp = obj.get(i);
            CLKey k = (CLKey) tmp;
            CLElement v = k.getValue();
            String vStr = v.content();
            if (vStr.matches("#[0-9a-fA-F]+")) {
                int color = Integer.parseInt(vStr.substring(1), 16);
                setCustomAttribute(this.name, TypedValues.Custom.TYPE_COLOR, color);
            } else if (v instanceof CLNumber) {
                setCustomAttribute(this.name, TypedValues.Custom.TYPE_FLOAT, v.getFloat());
            } else {
                setCustomAttribute(this.name, TypedValues.Custom.TYPE_STRING, vStr);
            }
        }
    }

    public StringBuilder serialize(StringBuilder ret) {
        return serialize(ret, false);
    }

    public StringBuilder serialize(StringBuilder ret, boolean sendPhoneOrientation) {
        ret.append("{\n");
        add(ret, "left", this.left);
        add(ret, "top", this.top);
        add(ret, "right", this.right);
        add(ret, "bottom", this.bottom);
        add(ret, "pivotX", this.pivotX);
        add(ret, "pivotY", this.pivotY);
        add(ret, "rotationX", this.rotationX);
        add(ret, "rotationY", this.rotationY);
        add(ret, "rotationZ", this.rotationZ);
        add(ret, "translationX", this.translationX);
        add(ret, "translationY", this.translationY);
        add(ret, "translationZ", this.translationZ);
        add(ret, "scaleX", this.scaleX);
        add(ret, "scaleY", this.scaleY);
        add(ret, "alpha", this.alpha);
        add(ret, "visibility", this.visibility);
        add(ret, "interpolatedPos", this.interpolatedPos);
        if (this.widget != null) {
            for (ConstraintAnchor.Type side : ConstraintAnchor.Type.values()) {
                serializeAnchor(ret, side);
            }
        }
        if (sendPhoneOrientation) {
            add(ret, "phone_orientation", phone_orientation);
        }
        if (sendPhoneOrientation) {
            add(ret, "phone_orientation", phone_orientation);
        }
        if (this.mCustom.size() != 0) {
            ret.append("custom : {\n");
            for (String s : this.mCustom.keySet()) {
                CustomVariable value = this.mCustom.get(s);
                ret.append(s);
                ret.append(": ");
                switch (value.getType()) {
                    case TypedValues.Custom.TYPE_INT /* 900 */:
                        ret.append(value.getIntegerValue());
                        ret.append(",\n");
                        break;
                    case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                    case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                        ret.append(value.getFloatValue());
                        ret.append(",\n");
                        break;
                    case TypedValues.Custom.TYPE_COLOR /* 902 */:
                        ret.append("'");
                        ret.append(CustomVariable.colorString(value.getIntegerValue()));
                        ret.append("',\n");
                        break;
                    case TypedValues.Custom.TYPE_STRING /* 903 */:
                        ret.append("'");
                        ret.append(value.getStringValue());
                        ret.append("',\n");
                        break;
                    case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                        ret.append("'");
                        ret.append(value.getBooleanValue());
                        ret.append("',\n");
                        break;
                }
            }
            ret.append("}\n");
        }
        ret.append("}\n");
        return ret;
    }

    private void serializeAnchor(StringBuilder ret, ConstraintAnchor.Type type) {
        ConstraintAnchor anchor = this.widget.getAnchor(type);
        if (anchor == null || anchor.mTarget == null) {
            return;
        }
        ret.append("Anchor");
        ret.append(type.name());
        ret.append(": ['");
        String str = anchor.mTarget.getOwner().stringId;
        ret.append(str == null ? "#PARENT" : str);
        ret.append("', '");
        ret.append(anchor.mTarget.getType().name());
        ret.append("', '");
        ret.append(anchor.mMargin);
        ret.append("'],\n");
    }

    private static void add(StringBuilder s, String title, int value) {
        s.append(title);
        s.append(": ");
        s.append(value);
        s.append(",\n");
    }

    private static void add(StringBuilder s, String title, float value) {
        if (Float.isNaN(value)) {
            return;
        }
        s.append(title);
        s.append(": ");
        s.append(value);
        s.append(",\n");
    }

    void printCustomAttributes() {
        String ss;
        StackTraceElement s = new Throwable().getStackTrace()[1];
        String ss2 = (".(" + s.getFileName() + ":" + s.getLineNumber() + ") " + s.getMethodName()) + " " + (hashCode() % 1000);
        if (this.widget != null) {
            ss = ss2 + "/" + (this.widget.hashCode() % 1000) + " ";
        } else {
            ss = ss2 + "/NULL ";
        }
        if (this.mCustom != null) {
            for (String key : this.mCustom.keySet()) {
                System.out.println(ss + this.mCustom.get(key).toString());
            }
        }
    }

    void logv(String str) {
        String ss;
        StackTraceElement s = new Throwable().getStackTrace()[1];
        String ss2 = (".(" + s.getFileName() + ":" + s.getLineNumber() + ") " + s.getMethodName()) + " " + (hashCode() % 1000);
        if (this.widget != null) {
            ss = ss2 + "/" + (this.widget.hashCode() % 1000);
        } else {
            ss = ss2 + "/NULL";
        }
        System.out.println(ss + " " + str);
    }

    public void setCustomValue(CustomAttribute valueAt, float[] mTempValues) {
    }

    void setMotionAttributes(TypedBundle motionProperties) {
        this.mMotionProperties = motionProperties;
    }

    public TypedBundle getMotionProperties() {
        return this.mMotionProperties;
    }
}
