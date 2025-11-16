package androidx.constraintlayout.core.motion.utils;

/* loaded from: classes.dex */
public interface TypedValues {
    public static final int BOOLEAN_MASK = 1;
    public static final int FLOAT_MASK = 4;
    public static final int INT_MASK = 2;
    public static final int STRING_MASK = 8;
    public static final String S_CUSTOM = "CUSTOM";
    public static final int TYPE_FRAME_POSITION = 100;
    public static final int TYPE_TARGET = 101;

    public interface OnSwipe {
        public static final String AUTOCOMPLETE_MODE = "autocompletemode";
        public static final String DRAG_DIRECTION = "dragdirection";
        public static final String DRAG_SCALE = "dragscale";
        public static final String DRAG_THRESHOLD = "dragthreshold";
        public static final String LIMIT_BOUNDS_TO = "limitboundsto";
        public static final String MAX_ACCELERATION = "maxacceleration";
        public static final String MAX_VELOCITY = "maxvelocity";
        public static final String MOVE_WHEN_SCROLLAT_TOP = "movewhenscrollattop";
        public static final String NESTED_SCROLL_FLAGS = "nestedscrollflags";
        public static final String ON_TOUCH_UP = "ontouchup";
        public static final String ROTATION_CENTER_ID = "rotationcenterid";
        public static final String SPRINGS_TOP_THRESHOLD = "springstopthreshold";
        public static final String SPRING_BOUNDARY = "springboundary";
        public static final String SPRING_DAMPING = "springdamping";
        public static final String SPRING_MASS = "springmass";
        public static final String SPRING_STIFFNESS = "springstiffness";
        public static final String TOUCH_ANCHOR_ID = "touchanchorid";
        public static final String TOUCH_ANCHOR_SIDE = "touchanchorside";
        public static final String TOUCH_REGION_ID = "touchregionid";
        public static final String[] ON_TOUCH_UP_ENUM = {"autoComplete", "autoCompleteToStart", "autoCompleteToEnd", "stop", "decelerate", "decelerateAndComplete", "neverCompleteToStart", "neverCompleteToEnd"};
        public static final String[] SPRING_BOUNDARY_ENUM = {"overshoot", "bounceStart", "bounceEnd", "bounceBoth"};
        public static final String[] AUTOCOMPLETE_MODE_ENUM = {"continuousVelocity", "spring"};
        public static final String[] NESTED_SCROLL_FLAGS_ENUM = {"none", "disablePostScroll", "disableScroll", "supportScrollUp"};
    }

    int getId(String str);

    boolean setValue(int i, float f);

    boolean setValue(int i, int i2);

    boolean setValue(int i, String str);

    boolean setValue(int i, boolean z);

    public interface AttributesType {
        public static final String NAME = "KeyAttributes";
        public static final String S_ALPHA = "alpha";
        public static final String S_CURVE_FIT = "curveFit";
        public static final String S_CUSTOM = "CUSTOM";
        public static final String S_EASING = "easing";
        public static final String S_ELEVATION = "elevation";
        public static final String S_PATH_ROTATE = "pathRotate";
        public static final String S_PIVOT_X = "pivotX";
        public static final String S_PIVOT_Y = "pivotY";
        public static final String S_PROGRESS = "progress";
        public static final String S_ROTATION_X = "rotationX";
        public static final String S_ROTATION_Y = "rotationY";
        public static final String S_ROTATION_Z = "rotationZ";
        public static final String S_SCALE_X = "scaleX";
        public static final String S_SCALE_Y = "scaleY";
        public static final String S_TRANSLATION_X = "translationX";
        public static final String S_TRANSLATION_Y = "translationY";
        public static final String S_TRANSLATION_Z = "translationZ";
        public static final String S_VISIBILITY = "visibility";
        public static final int TYPE_ALPHA = 303;
        public static final int TYPE_CURVE_FIT = 301;
        public static final int TYPE_EASING = 317;
        public static final int TYPE_ELEVATION = 307;
        public static final int TYPE_PATH_ROTATE = 316;
        public static final int TYPE_PIVOT_TARGET = 318;
        public static final int TYPE_PIVOT_X = 313;
        public static final int TYPE_PIVOT_Y = 314;
        public static final int TYPE_PROGRESS = 315;
        public static final int TYPE_ROTATION_X = 308;
        public static final int TYPE_ROTATION_Y = 309;
        public static final int TYPE_ROTATION_Z = 310;
        public static final int TYPE_SCALE_X = 311;
        public static final int TYPE_SCALE_Y = 312;
        public static final int TYPE_TRANSLATION_X = 304;
        public static final int TYPE_TRANSLATION_Y = 305;
        public static final int TYPE_TRANSLATION_Z = 306;
        public static final int TYPE_VISIBILITY = 302;
        public static final String S_FRAME = "frame";
        public static final String S_TARGET = "target";
        public static final String S_PIVOT_TARGET = "pivotTarget";
        public static final String[] KEY_WORDS = {"curveFit", "visibility", "alpha", "translationX", "translationY", "translationZ", "elevation", "rotationX", "rotationY", "rotationZ", "scaleX", "scaleY", "pivotX", "pivotY", "progress", "pathRotate", "easing", "CUSTOM", S_FRAME, S_TARGET, S_PIVOT_TARGET};

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:65:0x00ee  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                Method dump skipped, instructions count: 430
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.AttributesType.getId(java.lang.String):int");
        }

        static int getType(int name) {
            switch (name) {
                case 100:
                case 301:
                case 302:
                    return 2;
                case TypedValues.TYPE_TARGET /* 101 */:
                case TYPE_EASING /* 317 */:
                case TYPE_PIVOT_TARGET /* 318 */:
                    return 8;
                case 303:
                case 304:
                case 305:
                case 306:
                case 307:
                case 308:
                case 309:
                case 310:
                case 311:
                case 312:
                case 313:
                case 314:
                case 315:
                case TYPE_PATH_ROTATE /* 316 */:
                    return 4;
                default:
                    return -1;
            }
        }
    }

    public interface CycleType {
        public static final String NAME = "KeyCycle";
        public static final String S_ALPHA = "alpha";
        public static final String S_CURVE_FIT = "curveFit";
        public static final String S_EASING = "easing";
        public static final String S_ELEVATION = "elevation";
        public static final String S_PATH_ROTATE = "pathRotate";
        public static final String S_PIVOT_X = "pivotX";
        public static final String S_PIVOT_Y = "pivotY";
        public static final String S_PROGRESS = "progress";
        public static final String S_ROTATION_X = "rotationX";
        public static final String S_ROTATION_Y = "rotationY";
        public static final String S_ROTATION_Z = "rotationZ";
        public static final String S_SCALE_X = "scaleX";
        public static final String S_SCALE_Y = "scaleY";
        public static final String S_TRANSLATION_X = "translationX";
        public static final String S_TRANSLATION_Y = "translationY";
        public static final String S_TRANSLATION_Z = "translationZ";
        public static final String S_VISIBILITY = "visibility";
        public static final String S_WAVE_SHAPE = "waveShape";
        public static final int TYPE_ALPHA = 403;
        public static final int TYPE_CURVE_FIT = 401;
        public static final int TYPE_CUSTOM_WAVE_SHAPE = 422;
        public static final int TYPE_EASING = 420;
        public static final int TYPE_ELEVATION = 307;
        public static final int TYPE_PATH_ROTATE = 416;
        public static final int TYPE_PIVOT_X = 313;
        public static final int TYPE_PIVOT_Y = 314;
        public static final int TYPE_PROGRESS = 315;
        public static final int TYPE_ROTATION_X = 308;
        public static final int TYPE_ROTATION_Y = 309;
        public static final int TYPE_ROTATION_Z = 310;
        public static final int TYPE_SCALE_X = 311;
        public static final int TYPE_SCALE_Y = 312;
        public static final int TYPE_TRANSLATION_X = 304;
        public static final int TYPE_TRANSLATION_Y = 305;
        public static final int TYPE_TRANSLATION_Z = 306;
        public static final int TYPE_VISIBILITY = 402;
        public static final int TYPE_WAVE_OFFSET = 424;
        public static final int TYPE_WAVE_PERIOD = 423;
        public static final int TYPE_WAVE_PHASE = 425;
        public static final int TYPE_WAVE_SHAPE = 421;
        public static final String S_CUSTOM_WAVE_SHAPE = "customWave";
        public static final String S_WAVE_PERIOD = "period";
        public static final String S_WAVE_OFFSET = "offset";
        public static final String S_WAVE_PHASE = "phase";
        public static final String[] KEY_WORDS = {"curveFit", "visibility", "alpha", "translationX", "translationY", "translationZ", "elevation", "rotationX", "rotationY", "rotationZ", "scaleX", "scaleY", "pivotX", "pivotY", "progress", "pathRotate", "easing", "waveShape", S_CUSTOM_WAVE_SHAPE, S_WAVE_PERIOD, S_WAVE_OFFSET, S_WAVE_PHASE};

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:53:0x00bc  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                Method dump skipped, instructions count: 344
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.CycleType.getId(java.lang.String):int");
        }

        static int getType(int name) {
            switch (name) {
                case 100:
                case TYPE_CURVE_FIT /* 401 */:
                case TYPE_VISIBILITY /* 402 */:
                    return 2;
                case TypedValues.TYPE_TARGET /* 101 */:
                case TYPE_EASING /* 420 */:
                case TYPE_WAVE_SHAPE /* 421 */:
                    return 8;
                case 304:
                case 305:
                case 306:
                case 307:
                case 308:
                case 309:
                case 310:
                case 311:
                case 312:
                case 313:
                case 314:
                case 315:
                case TYPE_ALPHA /* 403 */:
                case TYPE_PATH_ROTATE /* 416 */:
                case TYPE_WAVE_PERIOD /* 423 */:
                case TYPE_WAVE_OFFSET /* 424 */:
                case TYPE_WAVE_PHASE /* 425 */:
                    return 4;
                default:
                    return -1;
            }
        }
    }

    public interface TriggerType {
        public static final String CROSS = "CROSS";
        public static final String[] KEY_WORDS = {"viewTransitionOnCross", "viewTransitionOnPositiveCross", "viewTransitionOnNegativeCross", "postLayout", "triggerSlack", "triggerCollisionView", "triggerCollisionId", "triggerID", "positiveCross", "negativeCross", "triggerReceiver", "CROSS"};
        public static final String NAME = "KeyTrigger";
        public static final String NEGATIVE_CROSS = "negativeCross";
        public static final String POSITIVE_CROSS = "positiveCross";
        public static final String POST_LAYOUT = "postLayout";
        public static final String TRIGGER_COLLISION_ID = "triggerCollisionId";
        public static final String TRIGGER_COLLISION_VIEW = "triggerCollisionView";
        public static final String TRIGGER_ID = "triggerID";
        public static final String TRIGGER_RECEIVER = "triggerReceiver";
        public static final String TRIGGER_SLACK = "triggerSlack";
        public static final int TYPE_CROSS = 312;
        public static final int TYPE_NEGATIVE_CROSS = 310;
        public static final int TYPE_POSITIVE_CROSS = 309;
        public static final int TYPE_POST_LAYOUT = 304;
        public static final int TYPE_TRIGGER_COLLISION_ID = 307;
        public static final int TYPE_TRIGGER_COLLISION_VIEW = 306;
        public static final int TYPE_TRIGGER_ID = 308;
        public static final int TYPE_TRIGGER_RECEIVER = 311;
        public static final int TYPE_TRIGGER_SLACK = 305;
        public static final int TYPE_VIEW_TRANSITION_ON_CROSS = 301;
        public static final int TYPE_VIEW_TRANSITION_ON_NEGATIVE_CROSS = 303;
        public static final int TYPE_VIEW_TRANSITION_ON_POSITIVE_CROSS = 302;
        public static final String VIEW_TRANSITION_ON_CROSS = "viewTransitionOnCross";
        public static final String VIEW_TRANSITION_ON_NEGATIVE_CROSS = "viewTransitionOnNegativeCross";
        public static final String VIEW_TRANSITION_ON_POSITIVE_CROSS = "viewTransitionOnPositiveCross";

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:41:0x0090  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                int r0 = r2.hashCode()
                r1 = -1
                switch(r0) {
                    case -1594793529: goto L85;
                    case -966421266: goto L7a;
                    case -786670827: goto L6f;
                    case -648752941: goto L64;
                    case -638126837: goto L59;
                    case -76025313: goto L4e;
                    case -9754574: goto L43;
                    case 64397344: goto L38;
                    case 364489912: goto L2d;
                    case 1301930599: goto L22;
                    case 1401391082: goto L17;
                    case 1535404999: goto La;
                    default: goto L8;
                }
            L8:
                goto L90
            La:
                java.lang.String r0 = "triggerReceiver"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 10
                goto L91
            L17:
                java.lang.String r0 = "postLayout"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 3
                goto L91
            L22:
                java.lang.String r0 = "viewTransitionOnCross"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 0
                goto L91
            L2d:
                java.lang.String r0 = "triggerSlack"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 4
                goto L91
            L38:
                java.lang.String r0 = "CROSS"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 11
                goto L91
            L43:
                java.lang.String r0 = "viewTransitionOnNegativeCross"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 2
                goto L91
            L4e:
                java.lang.String r0 = "triggerCollisionView"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 5
                goto L91
            L59:
                java.lang.String r0 = "negativeCross"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 9
                goto L91
            L64:
                java.lang.String r0 = "triggerID"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 7
                goto L91
            L6f:
                java.lang.String r0 = "triggerCollisionId"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 6
                goto L91
            L7a:
                java.lang.String r0 = "viewTransitionOnPositiveCross"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 1
                goto L91
            L85:
                java.lang.String r0 = "positiveCross"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 8
                goto L91
            L90:
                r0 = r1
            L91:
                switch(r0) {
                    case 0: goto Lb6;
                    case 1: goto Lb3;
                    case 2: goto Lb0;
                    case 3: goto Lad;
                    case 4: goto Laa;
                    case 5: goto La7;
                    case 6: goto La4;
                    case 7: goto La1;
                    case 8: goto L9e;
                    case 9: goto L9b;
                    case 10: goto L98;
                    case 11: goto L95;
                    default: goto L94;
                }
            L94:
                return r1
            L95:
                r0 = 312(0x138, float:4.37E-43)
                return r0
            L98:
                r0 = 311(0x137, float:4.36E-43)
                return r0
            L9b:
                r0 = 310(0x136, float:4.34E-43)
                return r0
            L9e:
                r0 = 309(0x135, float:4.33E-43)
                return r0
            La1:
                r0 = 308(0x134, float:4.32E-43)
                return r0
            La4:
                r0 = 307(0x133, float:4.3E-43)
                return r0
            La7:
                r0 = 306(0x132, float:4.29E-43)
                return r0
            Laa:
                r0 = 305(0x131, float:4.27E-43)
                return r0
            Lad:
                r0 = 304(0x130, float:4.26E-43)
                return r0
            Lb0:
                r0 = 303(0x12f, float:4.25E-43)
                return r0
            Lb3:
                r0 = 302(0x12e, float:4.23E-43)
                return r0
            Lb6:
                r0 = 301(0x12d, float:4.22E-43)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.TriggerType.getId(java.lang.String):int");
        }
    }

    public interface PositionType {
        public static final String[] KEY_WORDS = {"transitionEasing", "drawPath", "percentWidth", "percentHeight", "sizePercent", "percentX", "percentY"};
        public static final String NAME = "KeyPosition";
        public static final String S_DRAWPATH = "drawPath";
        public static final String S_PERCENT_HEIGHT = "percentHeight";
        public static final String S_PERCENT_WIDTH = "percentWidth";
        public static final String S_PERCENT_X = "percentX";
        public static final String S_PERCENT_Y = "percentY";
        public static final String S_SIZE_PERCENT = "sizePercent";
        public static final String S_TRANSITION_EASING = "transitionEasing";
        public static final int TYPE_CURVE_FIT = 508;
        public static final int TYPE_DRAWPATH = 502;
        public static final int TYPE_PATH_MOTION_ARC = 509;
        public static final int TYPE_PERCENT_HEIGHT = 504;
        public static final int TYPE_PERCENT_WIDTH = 503;
        public static final int TYPE_PERCENT_X = 506;
        public static final int TYPE_PERCENT_Y = 507;
        public static final int TYPE_POSITION_TYPE = 510;
        public static final int TYPE_SIZE_PERCENT = 505;
        public static final int TYPE_TRANSITION_EASING = 501;

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:26:0x0051  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                int r0 = r2.hashCode()
                r1 = -1
                switch(r0) {
                    case -1812823328: goto L46;
                    case -1127236479: goto L3c;
                    case -1017587252: goto L32;
                    case -827014263: goto L28;
                    case -200259324: goto L1d;
                    case 428090547: goto L13;
                    case 428090548: goto L9;
                    default: goto L8;
                }
            L8:
                goto L51
            L9:
                java.lang.String r0 = "percentY"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 6
                goto L52
            L13:
                java.lang.String r0 = "percentX"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 5
                goto L52
            L1d:
                java.lang.String r0 = "sizePercent"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 4
                goto L52
            L28:
                java.lang.String r0 = "drawPath"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 1
                goto L52
            L32:
                java.lang.String r0 = "percentHeight"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 3
                goto L52
            L3c:
                java.lang.String r0 = "percentWidth"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 2
                goto L52
            L46:
                java.lang.String r0 = "transitionEasing"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 0
                goto L52
            L51:
                r0 = r1
            L52:
                switch(r0) {
                    case 0: goto L68;
                    case 1: goto L65;
                    case 2: goto L62;
                    case 3: goto L5f;
                    case 4: goto L5c;
                    case 5: goto L59;
                    case 6: goto L56;
                    default: goto L55;
                }
            L55:
                return r1
            L56:
                r0 = 507(0x1fb, float:7.1E-43)
                return r0
            L59:
                r0 = 506(0x1fa, float:7.09E-43)
                return r0
            L5c:
                r0 = 505(0x1f9, float:7.08E-43)
                return r0
            L5f:
                r0 = 504(0x1f8, float:7.06E-43)
                return r0
            L62:
                r0 = 503(0x1f7, float:7.05E-43)
                return r0
            L65:
                r0 = 502(0x1f6, float:7.03E-43)
                return r0
            L68:
                r0 = 501(0x1f5, float:7.02E-43)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.PositionType.getId(java.lang.String):int");
        }

        static int getType(int name) {
            switch (name) {
                case 100:
                case TYPE_CURVE_FIT /* 508 */:
                    return 2;
                case TypedValues.TYPE_TARGET /* 101 */:
                case TYPE_TRANSITION_EASING /* 501 */:
                case TYPE_DRAWPATH /* 502 */:
                    return 8;
                case TYPE_PERCENT_WIDTH /* 503 */:
                case TYPE_PERCENT_HEIGHT /* 504 */:
                case TYPE_SIZE_PERCENT /* 505 */:
                case TYPE_PERCENT_X /* 506 */:
                case TYPE_PERCENT_Y /* 507 */:
                    return 4;
                default:
                    return -1;
            }
        }
    }

    public interface MotionType {
        public static final String NAME = "Motion";
        public static final int TYPE_ANIMATE_CIRCLEANGLE_TO = 606;
        public static final int TYPE_ANIMATE_RELATIVE_TO = 605;
        public static final int TYPE_DRAW_PATH = 608;
        public static final int TYPE_EASING = 603;
        public static final int TYPE_PATHMOTION_ARC = 607;
        public static final int TYPE_PATH_ROTATE = 601;
        public static final int TYPE_POLAR_RELATIVETO = 609;
        public static final int TYPE_QUANTIZE_INTERPOLATOR = 604;
        public static final int TYPE_QUANTIZE_INTERPOLATOR_ID = 612;
        public static final int TYPE_QUANTIZE_INTERPOLATOR_TYPE = 611;
        public static final int TYPE_QUANTIZE_MOTIONSTEPS = 610;
        public static final int TYPE_QUANTIZE_MOTION_PHASE = 602;
        public static final int TYPE_STAGGER = 600;
        public static final String S_STAGGER = "Stagger";
        public static final String S_PATH_ROTATE = "PathRotate";
        public static final String S_QUANTIZE_MOTION_PHASE = "QuantizeMotionPhase";
        public static final String S_EASING = "TransitionEasing";
        public static final String S_QUANTIZE_INTERPOLATOR = "QuantizeInterpolator";
        public static final String S_ANIMATE_RELATIVE_TO = "AnimateRelativeTo";
        public static final String S_ANIMATE_CIRCLEANGLE_TO = "AnimateCircleAngleTo";
        public static final String S_PATHMOTION_ARC = "PathMotionArc";
        public static final String S_DRAW_PATH = "DrawPath";
        public static final String S_POLAR_RELATIVETO = "PolarRelativeTo";
        public static final String S_QUANTIZE_MOTIONSTEPS = "QuantizeMotionSteps";
        public static final String S_QUANTIZE_INTERPOLATOR_TYPE = "QuantizeInterpolatorType";
        public static final String S_QUANTIZE_INTERPOLATOR_ID = "QuantizeInterpolatorID";
        public static final String[] KEY_WORDS = {S_STAGGER, S_PATH_ROTATE, S_QUANTIZE_MOTION_PHASE, S_EASING, S_QUANTIZE_INTERPOLATOR, S_ANIMATE_RELATIVE_TO, S_ANIMATE_CIRCLEANGLE_TO, S_PATHMOTION_ARC, S_DRAW_PATH, S_POLAR_RELATIVETO, S_QUANTIZE_MOTIONSTEPS, S_QUANTIZE_INTERPOLATOR_TYPE, S_QUANTIZE_INTERPOLATOR_ID};

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:44:0x0094  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                int r0 = r2.hashCode()
                r1 = -1
                switch(r0) {
                    case -2033446275: goto L8a;
                    case -1532277420: goto L80;
                    case -1529145600: goto L75;
                    case -1498310144: goto L6b;
                    case -1030753096: goto L61;
                    case -762370135: goto L56;
                    case -232872051: goto L4c;
                    case 1138491429: goto L41;
                    case 1539234834: goto L36;
                    case 1583722451: goto L2b;
                    case 1639368448: goto L20;
                    case 1900899336: goto L15;
                    case 2109694967: goto La;
                    default: goto L8;
                }
            L8:
                goto L94
            La:
                java.lang.String r0 = "PathMotionArc"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 7
                goto L95
            L15:
                java.lang.String r0 = "AnimateRelativeTo"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 5
                goto L95
            L20:
                java.lang.String r0 = "TransitionEasing"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 3
                goto L95
            L2b:
                java.lang.String r0 = "QuantizeInterpolatorID"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 12
                goto L95
            L36:
                java.lang.String r0 = "QuantizeInterpolatorType"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 11
                goto L95
            L41:
                java.lang.String r0 = "PolarRelativeTo"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 9
                goto L95
            L4c:
                java.lang.String r0 = "Stagger"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 0
                goto L95
            L56:
                java.lang.String r0 = "DrawPath"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 8
                goto L95
            L61:
                java.lang.String r0 = "QuantizeInterpolator"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 4
                goto L95
            L6b:
                java.lang.String r0 = "PathRotate"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 1
                goto L95
            L75:
                java.lang.String r0 = "QuantizeMotionSteps"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 10
                goto L95
            L80:
                java.lang.String r0 = "QuantizeMotionPhase"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 2
                goto L95
            L8a:
                java.lang.String r0 = "AnimateCircleAngleTo"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 6
                goto L95
            L94:
                r0 = r1
            L95:
                switch(r0) {
                    case 0: goto Lbd;
                    case 1: goto Lba;
                    case 2: goto Lb7;
                    case 3: goto Lb4;
                    case 4: goto Lb1;
                    case 5: goto Lae;
                    case 6: goto Lab;
                    case 7: goto La8;
                    case 8: goto La5;
                    case 9: goto La2;
                    case 10: goto L9f;
                    case 11: goto L9c;
                    case 12: goto L99;
                    default: goto L98;
                }
            L98:
                return r1
            L99:
                r0 = 612(0x264, float:8.58E-43)
                return r0
            L9c:
                r0 = 611(0x263, float:8.56E-43)
                return r0
            L9f:
                r0 = 610(0x262, float:8.55E-43)
                return r0
            La2:
                r0 = 609(0x261, float:8.53E-43)
                return r0
            La5:
                r0 = 608(0x260, float:8.52E-43)
                return r0
            La8:
                r0 = 607(0x25f, float:8.5E-43)
                return r0
            Lab:
                r0 = 606(0x25e, float:8.49E-43)
                return r0
            Lae:
                r0 = 605(0x25d, float:8.48E-43)
                return r0
            Lb1:
                r0 = 604(0x25c, float:8.46E-43)
                return r0
            Lb4:
                r0 = 603(0x25b, float:8.45E-43)
                return r0
            Lb7:
                r0 = 602(0x25a, float:8.44E-43)
                return r0
            Lba:
                r0 = 601(0x259, float:8.42E-43)
                return r0
            Lbd:
                r0 = 600(0x258, float:8.41E-43)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.MotionType.getId(java.lang.String):int");
        }
    }

    public interface Custom {
        public static final String NAME = "Custom";
        public static final String S_INT = "integer";
        public static final int TYPE_BOOLEAN = 904;
        public static final int TYPE_COLOR = 902;
        public static final int TYPE_DIMENSION = 905;
        public static final int TYPE_FLOAT = 901;
        public static final int TYPE_INT = 900;
        public static final int TYPE_REFERENCE = 906;
        public static final int TYPE_STRING = 903;
        public static final String S_FLOAT = "float";
        public static final String S_COLOR = "color";
        public static final String S_STRING = "string";
        public static final String S_BOOLEAN = "boolean";
        public static final String S_DIMENSION = "dimension";
        public static final String S_REFERENCE = "reference";
        public static final String[] KEY_WORDS = {S_FLOAT, S_COLOR, S_STRING, S_BOOLEAN, S_DIMENSION, S_REFERENCE};

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:26:0x0050  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                int r0 = r2.hashCode()
                r1 = -1
                switch(r0) {
                    case -1095013018: goto L46;
                    case -925155509: goto L3c;
                    case -891985903: goto L31;
                    case 64711720: goto L27;
                    case 94842723: goto L1d;
                    case 97526364: goto L13;
                    case 1958052158: goto L9;
                    default: goto L8;
                }
            L8:
                goto L50
            L9:
                java.lang.String r0 = "integer"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 0
                goto L51
            L13:
                java.lang.String r0 = "float"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 1
                goto L51
            L1d:
                java.lang.String r0 = "color"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 2
                goto L51
            L27:
                java.lang.String r0 = "boolean"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 4
                goto L51
            L31:
                java.lang.String r0 = "string"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 3
                goto L51
            L3c:
                java.lang.String r0 = "reference"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 6
                goto L51
            L46:
                java.lang.String r0 = "dimension"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 5
                goto L51
            L50:
                r0 = r1
            L51:
                switch(r0) {
                    case 0: goto L67;
                    case 1: goto L64;
                    case 2: goto L61;
                    case 3: goto L5e;
                    case 4: goto L5b;
                    case 5: goto L58;
                    case 6: goto L55;
                    default: goto L54;
                }
            L54:
                return r1
            L55:
                r0 = 906(0x38a, float:1.27E-42)
                return r0
            L58:
                r0 = 905(0x389, float:1.268E-42)
                return r0
            L5b:
                r0 = 904(0x388, float:1.267E-42)
                return r0
            L5e:
                r0 = 903(0x387, float:1.265E-42)
                return r0
            L61:
                r0 = 902(0x386, float:1.264E-42)
                return r0
            L64:
                r0 = 901(0x385, float:1.263E-42)
                return r0
            L67:
                r0 = 900(0x384, float:1.261E-42)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.Custom.getId(java.lang.String):int");
        }
    }

    public interface MotionScene {
        public static final String NAME = "MotionScene";
        public static final int TYPE_DEFAULT_DURATION = 600;
        public static final int TYPE_LAYOUT_DURING_TRANSITION = 601;
        public static final String S_DEFAULT_DURATION = "defaultDuration";
        public static final String S_LAYOUT_DURING_TRANSITION = "layoutDuringTransition";
        public static final String[] KEY_WORDS = {S_DEFAULT_DURATION, S_LAYOUT_DURING_TRANSITION};

        static int getType(int name) {
            switch (name) {
                case 600:
                    return 2;
                case 601:
                    return 1;
                default:
                    return -1;
            }
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:11:0x001d  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                int r0 = r2.hashCode()
                r1 = -1
                switch(r0) {
                    case 6076149: goto L13;
                    case 1028758976: goto L9;
                    default: goto L8;
                }
            L8:
                goto L1d
            L9:
                java.lang.String r0 = "layoutDuringTransition"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 1
                goto L1e
            L13:
                java.lang.String r0 = "defaultDuration"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 0
                goto L1e
            L1d:
                r0 = r1
            L1e:
                switch(r0) {
                    case 0: goto L25;
                    case 1: goto L22;
                    default: goto L21;
                }
            L21:
                return r1
            L22:
                r0 = 601(0x259, float:8.42E-43)
                return r0
            L25:
                r0 = 600(0x258, float:8.41E-43)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.MotionScene.getId(java.lang.String):int");
        }
    }

    public interface TransitionType {
        public static final String NAME = "Transitions";
        public static final int TYPE_AUTO_TRANSITION = 704;
        public static final int TYPE_DURATION = 700;
        public static final int TYPE_FROM = 701;
        public static final int TYPE_INTERPOLATOR = 705;
        public static final int TYPE_PATH_MOTION_ARC = 509;
        public static final int TYPE_STAGGERED = 706;
        public static final int TYPE_TO = 702;
        public static final int TYPE_TRANSITION_FLAGS = 707;
        public static final String S_DURATION = "duration";
        public static final String S_FROM = "from";
        public static final String S_TO = "to";
        public static final String S_PATH_MOTION_ARC = "pathMotionArc";
        public static final String S_AUTO_TRANSITION = "autoTransition";
        public static final String S_INTERPOLATOR = "motionInterpolator";
        public static final String S_STAGGERED = "staggered";
        public static final String S_TRANSITION_FLAGS = "transitionFlags";
        public static final String[] KEY_WORDS = {S_DURATION, S_FROM, S_TO, S_PATH_MOTION_ARC, S_AUTO_TRANSITION, S_INTERPOLATOR, S_STAGGERED, S_FROM, S_TRANSITION_FLAGS};

        static int getType(int name) {
            switch (name) {
                case 509:
                case TYPE_DURATION /* 700 */:
                    return 2;
                case TYPE_FROM /* 701 */:
                case TYPE_TO /* 702 */:
                case TYPE_INTERPOLATOR /* 705 */:
                case TYPE_TRANSITION_FLAGS /* 707 */:
                    return 8;
                case TYPE_STAGGERED /* 706 */:
                    return 4;
                default:
                    return -1;
            }
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:29:0x005c  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        static int getId(java.lang.String r2) {
            /*
                int r0 = r2.hashCode()
                r1 = -1
                switch(r0) {
                    case -1996906958: goto L51;
                    case -1992012396: goto L47;
                    case -1357874275: goto L3d;
                    case -1298065308: goto L33;
                    case 3707: goto L28;
                    case 3151786: goto L1e;
                    case 1310733335: goto L14;
                    case 1839260940: goto L9;
                    default: goto L8;
                }
            L8:
                goto L5c
            L9:
                java.lang.String r0 = "staggered"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 6
                goto L5d
            L14:
                java.lang.String r0 = "pathMotionArc"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 3
                goto L5d
            L1e:
                java.lang.String r0 = "from"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 1
                goto L5d
            L28:
                java.lang.String r0 = "to"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 2
                goto L5d
            L33:
                java.lang.String r0 = "autoTransition"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 4
                goto L5d
            L3d:
                java.lang.String r0 = "motionInterpolator"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 5
                goto L5d
            L47:
                java.lang.String r0 = "duration"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 0
                goto L5d
            L51:
                java.lang.String r0 = "transitionFlags"
                boolean r0 = r2.equals(r0)
                if (r0 == 0) goto L8
                r0 = 7
                goto L5d
            L5c:
                r0 = r1
            L5d:
                switch(r0) {
                    case 0: goto L76;
                    case 1: goto L73;
                    case 2: goto L70;
                    case 3: goto L6d;
                    case 4: goto L6a;
                    case 5: goto L67;
                    case 6: goto L64;
                    case 7: goto L61;
                    default: goto L60;
                }
            L60:
                return r1
            L61:
                r0 = 707(0x2c3, float:9.91E-43)
                return r0
            L64:
                r0 = 706(0x2c2, float:9.9E-43)
                return r0
            L67:
                r0 = 705(0x2c1, float:9.88E-43)
                return r0
            L6a:
                r0 = 704(0x2c0, float:9.87E-43)
                return r0
            L6d:
                r0 = 509(0x1fd, float:7.13E-43)
                return r0
            L70:
                r0 = 702(0x2be, float:9.84E-43)
                return r0
            L73:
                r0 = 701(0x2bd, float:9.82E-43)
                return r0
            L76:
                r0 = 700(0x2bc, float:9.81E-43)
                return r0
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.motion.utils.TypedValues.TransitionType.getId(java.lang.String):int");
        }
    }
}
