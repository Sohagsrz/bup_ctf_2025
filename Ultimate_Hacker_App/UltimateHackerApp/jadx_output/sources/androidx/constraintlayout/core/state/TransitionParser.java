package androidx.constraintlayout.core.state;

import androidx.constraintlayout.core.motion.CustomVariable;
import androidx.constraintlayout.core.motion.utils.TypedBundle;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.parser.CLArray;
import androidx.constraintlayout.core.parser.CLContainer;
import androidx.constraintlayout.core.parser.CLElement;
import androidx.constraintlayout.core.parser.CLKey;
import androidx.constraintlayout.core.parser.CLNumber;
import androidx.constraintlayout.core.parser.CLObject;
import androidx.constraintlayout.core.parser.CLParsingException;
import androidx.constraintlayout.core.state.Transition;
import java.lang.reflect.Array;

/* loaded from: classes.dex */
public class TransitionParser {
    @Deprecated
    public static void parse(CLObject json, Transition transition, CorePixelDp dpToPixel) throws CLParsingException {
        parse(json, transition);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:25:0x005e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void parse(androidx.constraintlayout.core.parser.CLObject r11, androidx.constraintlayout.core.state.Transition r12) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            r12.resetProperties()
            java.lang.String r0 = "pathMotionArc"
            java.lang.String r0 = r11.getStringOrNull(r0)
            androidx.constraintlayout.core.motion.utils.TypedBundle r1 = new androidx.constraintlayout.core.motion.utils.TypedBundle
            r1.<init>()
            r2 = 0
            if (r0 == 0) goto L7d
            r2 = 1
            int r3 = r0.hashCode()
            r4 = 5
            r5 = 4
            r6 = 3
            r7 = 2
            r8 = 1
            r9 = 0
            switch(r3) {
                case -1857024520: goto L53;
                case -1007052250: goto L48;
                case 3145837: goto L3e;
                case 3387192: goto L34;
                case 92611485: goto L2a;
                case 93621297: goto L20;
                default: goto L1f;
            }
        L1f:
            goto L5e
        L20:
            java.lang.String r3 = "below"
            boolean r3 = r0.equals(r3)
            if (r3 == 0) goto L1f
            r3 = r5
            goto L5f
        L2a:
            java.lang.String r3 = "above"
            boolean r3 = r0.equals(r3)
            if (r3 == 0) goto L1f
            r3 = r4
            goto L5f
        L34:
            java.lang.String r3 = "none"
            boolean r3 = r0.equals(r3)
            if (r3 == 0) goto L1f
            r3 = r9
            goto L5f
        L3e:
            java.lang.String r3 = "flip"
            boolean r3 = r0.equals(r3)
            if (r3 == 0) goto L1f
            r3 = r6
            goto L5f
        L48:
            java.lang.String r3 = "startHorizontal"
            boolean r3 = r0.equals(r3)
            if (r3 == 0) goto L1f
            r3 = r7
            goto L5f
        L53:
            java.lang.String r3 = "startVertical"
            boolean r3 = r0.equals(r3)
            if (r3 == 0) goto L1f
            r3 = r8
            goto L5f
        L5e:
            r3 = -1
        L5f:
            r10 = 509(0x1fd, float:7.13E-43)
            switch(r3) {
                case 0: goto L79;
                case 1: goto L75;
                case 2: goto L71;
                case 3: goto L6d;
                case 4: goto L69;
                case 5: goto L65;
                default: goto L64;
            }
        L64:
            goto L7d
        L65:
            r1.add(r10, r4)
            goto L7d
        L69:
            r1.add(r10, r5)
            goto L7d
        L6d:
            r1.add(r10, r6)
            goto L7d
        L71:
            r1.add(r10, r7)
            goto L7d
        L75:
            r1.add(r10, r8)
            goto L7d
        L79:
            r1.add(r10, r9)
        L7d:
            java.lang.String r3 = "interpolator"
            java.lang.String r3 = r11.getStringOrNull(r3)
            if (r3 == 0) goto L8b
            r2 = 1
            r4 = 705(0x2c1, float:9.88E-43)
            r1.add(r4, r3)
        L8b:
            java.lang.String r4 = "staggered"
            float r4 = r11.getFloatOrNaN(r4)
            boolean r5 = java.lang.Float.isNaN(r4)
            if (r5 != 0) goto L9e
            r2 = 1
            r5 = 706(0x2c2, float:9.9E-43)
            r1.add(r5, r4)
        L9e:
            if (r2 == 0) goto La3
            r12.setTransitionProperties(r1)
        La3:
            java.lang.String r5 = "onSwipe"
            androidx.constraintlayout.core.parser.CLObject r5 = r11.getObjectOrNull(r5)
            if (r5 == 0) goto Lae
            parseOnSwipe(r5, r12)
        Lae:
            parseKeyFrames(r11, r12)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.TransitionParser.parse(androidx.constraintlayout.core.parser.CLObject, androidx.constraintlayout.core.state.Transition):void");
    }

    private static void parseOnSwipe(CLContainer onSwipe, Transition transition) {
        String anchor = onSwipe.getStringOrNull("anchor");
        int side = map(onSwipe.getStringOrNull("side"), Transition.OnSwipe.SIDES);
        int direction = map(onSwipe.getStringOrNull("direction"), Transition.OnSwipe.DIRECTIONS);
        float scale = onSwipe.getFloatOrNaN("scale");
        float threshold = onSwipe.getFloatOrNaN("threshold");
        float maxVelocity = onSwipe.getFloatOrNaN("maxVelocity");
        float maxAccel = onSwipe.getFloatOrNaN("maxAccel");
        String limitBounds = onSwipe.getStringOrNull("limitBounds");
        int autoCompleteMode = map(onSwipe.getStringOrNull("mode"), Transition.OnSwipe.MODE);
        int touchUp = map(onSwipe.getStringOrNull("touchUp"), Transition.OnSwipe.TOUCH_UP);
        float springMass = onSwipe.getFloatOrNaN("springMass");
        float springStiffness = onSwipe.getFloatOrNaN("springStiffness");
        float springDamping = onSwipe.getFloatOrNaN("springDamping");
        float stopThreshold = onSwipe.getFloatOrNaN("stopThreshold");
        int springBoundary = map(onSwipe.getStringOrNull("springBoundary"), Transition.OnSwipe.BOUNDARY);
        String around = onSwipe.getStringOrNull("around");
        Transition.OnSwipe swipe = transition.createOnSwipe();
        swipe.setAnchorId(anchor);
        swipe.setAnchorSide(side);
        swipe.setDragDirection(direction);
        swipe.setDragScale(scale);
        swipe.setDragThreshold(threshold);
        swipe.setMaxVelocity(maxVelocity);
        swipe.setMaxAcceleration(maxAccel);
        swipe.setLimitBoundsTo(limitBounds);
        swipe.setAutoCompleteMode(autoCompleteMode);
        swipe.setOnTouchUp(touchUp);
        swipe.setSpringMass(springMass);
        swipe.setSpringStiffness(springStiffness);
        swipe.setSpringDamping(springDamping);
        swipe.setSpringStopThreshold(stopThreshold);
        swipe.setSpringBoundary(springBoundary);
        swipe.setRotationCenterId(around);
    }

    private static int map(String val, String... types) {
        for (int i = 0; i < types.length; i++) {
            if (types[i].equals(val)) {
                return i;
            }
        }
        return 0;
    }

    private static void map(TypedBundle bundle, int type, String val, String... types) {
        for (int i = 0; i < types.length; i++) {
            if (types[i].equals(val)) {
                bundle.add(type, i);
            }
        }
    }

    public static void parseKeyFrames(CLObject transitionCLObject, Transition transition) throws CLParsingException {
        CLContainer keyframes = transitionCLObject.getObjectOrNull("KeyFrames");
        if (keyframes == null) {
            return;
        }
        CLArray keyPositions = keyframes.getArrayOrNull("KeyPositions");
        if (keyPositions != null) {
            for (int i = 0; i < keyPositions.size(); i++) {
                CLElement keyPosition = keyPositions.get(i);
                if (keyPosition instanceof CLObject) {
                    parseKeyPosition((CLObject) keyPosition, transition);
                }
            }
        }
        CLArray keyAttributes = keyframes.getArrayOrNull(TypedValues.AttributesType.NAME);
        if (keyAttributes != null) {
            for (int i2 = 0; i2 < keyAttributes.size(); i2++) {
                CLElement keyAttribute = keyAttributes.get(i2);
                if (keyAttribute instanceof CLObject) {
                    parseKeyAttribute((CLObject) keyAttribute, transition);
                }
            }
        }
        CLArray keyCycles = keyframes.getArrayOrNull("KeyCycles");
        if (keyCycles != null) {
            for (int i3 = 0; i3 < keyCycles.size(); i3++) {
                CLElement keyCycle = keyCycles.get(i3);
                if (keyCycle instanceof CLObject) {
                    parseKeyCycle((CLObject) keyCycle, transition);
                }
            }
        }
    }

    private static void parseKeyPosition(CLObject keyPosition, Transition transition) throws CLParsingException {
        TypedBundle bundle = new TypedBundle();
        CLArray targets = keyPosition.getArray(TypedValues.AttributesType.S_TARGET);
        CLArray frames = keyPosition.getArray("frames");
        CLArray percentX = keyPosition.getArrayOrNull("percentX");
        CLArray percentY = keyPosition.getArrayOrNull("percentY");
        CLArray percentWidth = keyPosition.getArrayOrNull("percentWidth");
        CLArray percentHeight = keyPosition.getArrayOrNull("percentHeight");
        String pathMotionArc = keyPosition.getStringOrNull(TypedValues.TransitionType.S_PATH_MOTION_ARC);
        String transitionEasing = keyPosition.getStringOrNull("transitionEasing");
        String curveFit = keyPosition.getStringOrNull("curveFit");
        String type = keyPosition.getStringOrNull("type");
        if (type == null) {
            type = "parentRelative";
        }
        if (percentX != null && frames.size() != percentX.size()) {
            return;
        }
        if (percentY != null && frames.size() != percentY.size()) {
            return;
        }
        int i = 0;
        while (i < targets.size()) {
            String target = targets.getString(i);
            int pos_type = map(type, "deltaRelative", "pathRelative", "parentRelative");
            bundle.clear();
            bundle.add(TypedValues.PositionType.TYPE_POSITION_TYPE, pos_type);
            if (curveFit != null) {
                map(bundle, TypedValues.PositionType.TYPE_CURVE_FIT, curveFit, "spline", "linear");
            }
            bundle.addIfNotNull(TypedValues.PositionType.TYPE_TRANSITION_EASING, transitionEasing);
            if (pathMotionArc != null) {
                map(bundle, 509, pathMotionArc, "none", "startVertical", "startHorizontal", "flip", "below", "above");
            }
            int j = 0;
            while (j < frames.size()) {
                int frame = frames.getInt(j);
                bundle.add(100, frame);
                set(bundle, TypedValues.PositionType.TYPE_PERCENT_X, percentX, j);
                set(bundle, TypedValues.PositionType.TYPE_PERCENT_Y, percentY, j);
                set(bundle, TypedValues.PositionType.TYPE_PERCENT_WIDTH, percentWidth, j);
                set(bundle, TypedValues.PositionType.TYPE_PERCENT_HEIGHT, percentHeight, j);
                transition.addKeyPosition(target, bundle);
                j++;
                targets = targets;
            }
            i++;
            targets = targets;
        }
    }

    private static void set(TypedBundle bundle, int type, CLArray array, int index) throws CLParsingException {
        if (array != null) {
            bundle.add(type, array.getFloat(index));
        }
    }

    private static void parseKeyAttribute(CLObject cLObject, Transition transition) throws CLParsingException {
        CLArray arrayOrNull;
        String[] strArr;
        int[] iArr;
        CLObject cLObject2;
        int i;
        CLObject cLObject3;
        boolean[] zArr;
        int i2;
        CLArray arrayOrNull2 = cLObject.getArrayOrNull(TypedValues.AttributesType.S_TARGET);
        if (arrayOrNull2 != null && (arrayOrNull = cLObject.getArrayOrNull("frames")) != null) {
            String stringOrNull = cLObject.getStringOrNull("transitionEasing");
            int i3 = 0;
            boolean z = true;
            String[] strArr2 = {"scaleX", "scaleY", "translationX", "translationY", "translationZ", "rotationX", "rotationY", "rotationZ", "alpha"};
            int[] iArr2 = {311, 312, 304, 305, 306, 308, 309, 310, 303};
            boolean[] zArr2 = {false, false, true, true, true, false, false, false, false};
            TypedBundle[] typedBundleArr = new TypedBundle[arrayOrNull.size()];
            CustomVariable[][] customVariableArr = null;
            for (int i4 = 0; i4 < arrayOrNull.size(); i4++) {
                typedBundleArr[i4] = new TypedBundle();
            }
            int i5 = 0;
            while (i5 < strArr2.length) {
                String str = strArr2[i5];
                int i6 = iArr2[i5];
                boolean z2 = zArr2[i5];
                boolean z3 = z;
                CLArray arrayOrNull3 = cLObject.getArrayOrNull(str);
                if (arrayOrNull3 != null) {
                    i2 = i3;
                    if (arrayOrNull3.size() != typedBundleArr.length) {
                        throw new CLParsingException("incorrect size for " + str + " array, not matching targets array!", cLObject);
                    }
                    zArr = zArr2;
                } else {
                    zArr = zArr2;
                    i2 = i3;
                }
                if (arrayOrNull3 != null) {
                    for (int i7 = 0; i7 < typedBundleArr.length; i7++) {
                        float pixels = arrayOrNull3.getFloat(i7);
                        if (z2) {
                            pixels = transition.mToPixel.toPixels(pixels);
                        }
                        typedBundleArr[i7].add(i6, pixels);
                    }
                } else {
                    float floatOrNaN = cLObject.getFloatOrNaN(str);
                    if (!Float.isNaN(floatOrNaN)) {
                        if (z2) {
                            floatOrNaN = transition.mToPixel.toPixels(floatOrNaN);
                        }
                        for (TypedBundle typedBundle : typedBundleArr) {
                            typedBundle.add(i6, floatOrNaN);
                        }
                    }
                }
                i5++;
                z = z3;
                i3 = i2;
                zArr2 = zArr;
            }
            int i8 = i3;
            boolean z4 = z;
            CLElement orNull = cLObject.getOrNull("custom");
            if (orNull != null && (orNull instanceof CLObject)) {
                CLObject cLObject4 = (CLObject) orNull;
                int size = cLObject4.size();
                int size2 = arrayOrNull.size();
                int[] iArr3 = new int[2];
                iArr3[z4 ? 1 : 0] = size;
                iArr3[i8] = size2;
                customVariableArr = (CustomVariable[][]) Array.newInstance((Class<?>) CustomVariable.class, iArr3);
                int i9 = 0;
                while (i9 < size) {
                    CLKey cLKey = (CLKey) cLObject4.get(i9);
                    String strContent = cLKey.content();
                    CLElement cLElement = orNull;
                    if (cLKey.getValue() instanceof CLArray) {
                        CLArray cLArray = (CLArray) cLKey.getValue();
                        int size3 = cLArray.size();
                        strArr = strArr2;
                        if (size3 != typedBundleArr.length || size3 <= 0) {
                            iArr = iArr2;
                            cLObject2 = cLObject4;
                        } else if (cLArray.get(i8) instanceof CLNumber) {
                            int i10 = 0;
                            while (i10 < typedBundleArr.length) {
                                customVariableArr[i10][i9] = new CustomVariable(strContent, TypedValues.Custom.TYPE_FLOAT, cLArray.get(i10).getFloat());
                                i10++;
                                iArr2 = iArr2;
                            }
                            iArr = iArr2;
                            cLObject2 = cLObject4;
                        } else {
                            iArr = iArr2;
                            int i11 = 0;
                            while (i11 < typedBundleArr.length) {
                                long colorString = ConstraintSetParser.parseColorString(cLArray.get(i11).content());
                                if (colorString == -1) {
                                    i = i11;
                                    cLObject3 = cLObject4;
                                } else {
                                    i = i11;
                                    cLObject3 = cLObject4;
                                    customVariableArr[i11][i9] = new CustomVariable(strContent, TypedValues.Custom.TYPE_COLOR, (int) colorString);
                                }
                                i11 = i + 1;
                                cLObject4 = cLObject3;
                            }
                            cLObject2 = cLObject4;
                        }
                    } else {
                        strArr = strArr2;
                        iArr = iArr2;
                        cLObject2 = cLObject4;
                        CLElement value = cLKey.getValue();
                        if (value instanceof CLNumber) {
                            float f = value.getFloat();
                            int i12 = 0;
                            while (i12 < typedBundleArr.length) {
                                customVariableArr[i12][i9] = new CustomVariable(strContent, TypedValues.Custom.TYPE_FLOAT, f);
                                i12++;
                                value = value;
                            }
                        } else {
                            long colorString2 = ConstraintSetParser.parseColorString(value.content());
                            if (colorString2 != -1) {
                                int i13 = 0;
                                while (i13 < typedBundleArr.length) {
                                    customVariableArr[i13][i9] = new CustomVariable(strContent, TypedValues.Custom.TYPE_COLOR, (int) colorString2);
                                    i13++;
                                    colorString2 = colorString2;
                                }
                            }
                        }
                    }
                    i9++;
                    orNull = cLElement;
                    strArr2 = strArr;
                    iArr2 = iArr;
                    cLObject4 = cLObject2;
                    i8 = 0;
                }
            }
            String stringOrNull2 = cLObject.getStringOrNull("curveFit");
            for (int i14 = 0; i14 < arrayOrNull2.size(); i14++) {
                for (int i15 = 0; i15 < typedBundleArr.length; i15++) {
                    String string = arrayOrNull2.getString(i14);
                    TypedBundle typedBundle2 = typedBundleArr[i15];
                    if (stringOrNull2 != null) {
                        String[] strArr3 = new String[2];
                        strArr3[0] = "spline";
                        strArr3[z4 ? 1 : 0] = "linear";
                        typedBundle2.add(TypedValues.PositionType.TYPE_CURVE_FIT, map(stringOrNull2, strArr3));
                    }
                    typedBundle2.addIfNotNull(TypedValues.PositionType.TYPE_TRANSITION_EASING, stringOrNull);
                    typedBundle2.add(100, arrayOrNull.getInt(i15));
                    transition.addKeyAttribute(string, typedBundle2, customVariableArr != null ? customVariableArr[i15] : null);
                }
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:71:0x016d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void parseKeyCycle(androidx.constraintlayout.core.parser.CLObject r19, androidx.constraintlayout.core.state.Transition r20) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 524
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.TransitionParser.parseKeyCycle(androidx.constraintlayout.core.parser.CLObject, androidx.constraintlayout.core.state.Transition):void");
    }
}
