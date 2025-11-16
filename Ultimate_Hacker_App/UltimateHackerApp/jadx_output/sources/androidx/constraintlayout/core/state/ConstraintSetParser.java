package androidx.constraintlayout.core.state;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.parser.CLArray;
import androidx.constraintlayout.core.parser.CLElement;
import androidx.constraintlayout.core.parser.CLKey;
import androidx.constraintlayout.core.parser.CLNumber;
import androidx.constraintlayout.core.parser.CLObject;
import androidx.constraintlayout.core.parser.CLParser;
import androidx.constraintlayout.core.parser.CLParsingException;
import androidx.constraintlayout.core.parser.CLString;
import androidx.constraintlayout.core.state.State;
import androidx.constraintlayout.core.state.helpers.ChainReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes.dex */
public class ConstraintSetParser {
    private static final boolean PARSER_DEBUG = false;

    interface GeneratedValue {
        float value();
    }

    public enum MotionLayoutDebugFlags {
        NONE,
        SHOW_ALL,
        UNKNOWN
    }

    public static class DesignElement {
        String mId;
        HashMap<String, String> mParams;
        String mType;

        public String getId() {
            return this.mId;
        }

        public String getType() {
            return this.mType;
        }

        public HashMap<String, String> getParams() {
            return this.mParams;
        }

        DesignElement(String id, String type, HashMap<String, String> params) {
            this.mId = id;
            this.mType = type;
            this.mParams = params;
        }
    }

    public static class LayoutVariables {
        HashMap<String, Integer> mMargins = new HashMap<>();
        HashMap<String, GeneratedValue> mGenerators = new HashMap<>();
        HashMap<String, ArrayList<String>> mArrayIds = new HashMap<>();

        void put(String elementName, int element) {
            this.mMargins.put(elementName, Integer.valueOf(element));
        }

        void put(String elementName, float start, float incrementBy) {
            if (this.mGenerators.containsKey(elementName) && (this.mGenerators.get(elementName) instanceof OverrideValue)) {
                return;
            }
            this.mGenerators.put(elementName, new Generator(start, incrementBy));
        }

        void put(String elementName, float from, float to, float step, String prefix, String postfix) {
            if (this.mGenerators.containsKey(elementName) && (this.mGenerators.get(elementName) instanceof OverrideValue)) {
                return;
            }
            FiniteGenerator generator = new FiniteGenerator(from, to, step, prefix, postfix);
            this.mGenerators.put(elementName, generator);
            this.mArrayIds.put(elementName, generator.array());
        }

        public void putOverride(String elementName, float value) {
            GeneratedValue generator = new OverrideValue(value);
            this.mGenerators.put(elementName, generator);
        }

        float get(Object elementName) {
            if (elementName instanceof CLString) {
                String stringValue = ((CLString) elementName).content();
                if (this.mGenerators.containsKey(stringValue)) {
                    return this.mGenerators.get(stringValue).value();
                }
                if (this.mMargins.containsKey(stringValue)) {
                    return this.mMargins.get(stringValue).floatValue();
                }
                return 0.0f;
            }
            if (elementName instanceof CLNumber) {
                return ((CLNumber) elementName).getFloat();
            }
            return 0.0f;
        }

        ArrayList<String> getList(String elementName) {
            if (this.mArrayIds.containsKey(elementName)) {
                return this.mArrayIds.get(elementName);
            }
            return null;
        }

        void put(String elementName, ArrayList<String> elements) {
            this.mArrayIds.put(elementName, elements);
        }
    }

    static class Generator implements GeneratedValue {
        float mCurrent;
        float mIncrementBy;
        float mStart;
        boolean mStop = false;

        Generator(float start, float incrementBy) {
            this.mStart = 0.0f;
            this.mIncrementBy = 0.0f;
            this.mCurrent = 0.0f;
            this.mStart = start;
            this.mIncrementBy = incrementBy;
            this.mCurrent = start;
        }

        @Override // androidx.constraintlayout.core.state.ConstraintSetParser.GeneratedValue
        public float value() {
            if (!this.mStop) {
                this.mCurrent += this.mIncrementBy;
            }
            return this.mCurrent;
        }
    }

    static class FiniteGenerator implements GeneratedValue {
        float mFrom;
        float mInitial;
        float mMax;
        String mPostfix;
        String mPrefix;
        float mStep;
        float mTo;
        boolean mStop = false;
        float mCurrent = 0.0f;

        FiniteGenerator(float from, float to, float step, String prefix, String postfix) {
            this.mFrom = 0.0f;
            this.mTo = 0.0f;
            this.mStep = 0.0f;
            this.mFrom = from;
            this.mTo = to;
            this.mStep = step;
            this.mPrefix = prefix == null ? "" : prefix;
            this.mPostfix = postfix != null ? postfix : "";
            this.mMax = to;
            this.mInitial = from;
        }

        @Override // androidx.constraintlayout.core.state.ConstraintSetParser.GeneratedValue
        public float value() {
            if (this.mCurrent >= this.mMax) {
                this.mStop = true;
            }
            if (!this.mStop) {
                this.mCurrent += this.mStep;
            }
            return this.mCurrent;
        }

        public ArrayList<String> array() {
            ArrayList<String> array = new ArrayList<>();
            int value = (int) this.mInitial;
            int maxInt = (int) this.mMax;
            for (int i = value; i <= maxInt; i++) {
                array.add(this.mPrefix + value + this.mPostfix);
                value += (int) this.mStep;
            }
            return array;
        }
    }

    static class OverrideValue implements GeneratedValue {
        float mValue;

        OverrideValue(float value) {
            this.mValue = value;
        }

        @Override // androidx.constraintlayout.core.state.ConstraintSetParser.GeneratedValue
        public float value() {
            return this.mValue;
        }
    }

    public static void parseJSON(String content, Transition transition, int state) {
        try {
            CLObject json = CLParser.parse(content);
            ArrayList<String> elements = json.names();
            if (elements == null) {
                return;
            }
            Iterator<String> it = elements.iterator();
            while (it.hasNext()) {
                String elementName = it.next();
                CLElement base_element = json.get(elementName);
                if (base_element instanceof CLObject) {
                    CLObject element = (CLObject) base_element;
                    CLObject customProperties = element.getObjectOrNull("custom");
                    if (customProperties != null) {
                        ArrayList<String> properties = customProperties.names();
                        Iterator<String> it2 = properties.iterator();
                        while (it2.hasNext()) {
                            String property = it2.next();
                            CLElement value = customProperties.get(property);
                            if (value instanceof CLNumber) {
                                transition.addCustomFloat(state, elementName, property, value.getFloat());
                            } else if (value instanceof CLString) {
                                long color = parseColorString(value.content());
                                if (color != -1) {
                                    transition.addCustomColor(state, elementName, property, (int) color);
                                }
                            }
                        }
                    }
                }
            }
        } catch (CLParsingException e) {
            System.err.println("Error parsing JSON " + e);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:12:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void parseMotionSceneJSON(androidx.constraintlayout.core.state.CoreMotionScene r7, java.lang.String r8) {
        /*
            androidx.constraintlayout.core.parser.CLObject r0 = androidx.constraintlayout.core.parser.CLParser.parse(r8)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            java.util.ArrayList r1 = r0.names()     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            if (r1 != 0) goto Lb
            return
        Lb:
            java.util.Iterator r2 = r1.iterator()     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
        Lf:
            boolean r3 = r2.hasNext()     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            if (r3 == 0) goto L5e
            java.lang.Object r3 = r2.next()     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            java.lang.String r3 = (java.lang.String) r3     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            androidx.constraintlayout.core.parser.CLElement r4 = r0.get(r3)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            boolean r5 = r4 instanceof androidx.constraintlayout.core.parser.CLObject     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            if (r5 == 0) goto L5d
            r5 = r4
            androidx.constraintlayout.core.parser.CLObject r5 = (androidx.constraintlayout.core.parser.CLObject) r5     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            int r6 = r3.hashCode()     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            switch(r6) {
                case -2137403731: goto L42;
                case -241441378: goto L38;
                case 1101852654: goto L2e;
                default: goto L2d;
            }     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
        L2d:
            goto L4c
        L2e:
            java.lang.String r6 = "ConstraintSets"
            boolean r6 = r3.equals(r6)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            if (r6 == 0) goto L2d
            r6 = 0
            goto L4d
        L38:
            java.lang.String r6 = "Transitions"
            boolean r6 = r3.equals(r6)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            if (r6 == 0) goto L2d
            r6 = 1
            goto L4d
        L42:
            java.lang.String r6 = "Header"
            boolean r6 = r3.equals(r6)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            if (r6 == 0) goto L2d
            r6 = 2
            goto L4d
        L4c:
            r6 = -1
        L4d:
            switch(r6) {
                case 0: goto L59;
                case 1: goto L55;
                case 2: goto L51;
                default: goto L50;
            }     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
        L50:
            goto L5d
        L51:
            parseHeader(r7, r5)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            goto L5d
        L55:
            parseTransitions(r7, r5)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
            goto L5d
        L59:
            parseConstraintSets(r7, r5)     // Catch: androidx.constraintlayout.core.parser.CLParsingException -> L5f
        L5d:
            goto Lf
        L5e:
            goto L78
        L5f:
            r0 = move-exception
            java.io.PrintStream r1 = java.lang.System.err
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r3 = "Error parsing JSON "
            java.lang.StringBuilder r2 = r2.append(r3)
            java.lang.StringBuilder r2 = r2.append(r0)
            java.lang.String r2 = r2.toString()
            r1.println(r2)
        L78:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseMotionSceneJSON(androidx.constraintlayout.core.state.CoreMotionScene, java.lang.String):void");
    }

    static void parseConstraintSets(CoreMotionScene scene, CLObject json) throws CLParsingException {
        ArrayList<String> constraintSetNames = json.names();
        if (constraintSetNames == null) {
            return;
        }
        Iterator<String> it = constraintSetNames.iterator();
        while (it.hasNext()) {
            String csName = it.next();
            CLObject constraintSet = json.getObject(csName);
            boolean added = false;
            String ext = constraintSet.getStringOrNull("Extends");
            if (ext != null && !ext.isEmpty()) {
                String base = scene.getConstraintSet(ext);
                if (base != null) {
                    CLObject baseJson = CLParser.parse(base);
                    ArrayList<String> widgetsOverride = constraintSet.names();
                    if (widgetsOverride != null) {
                        Iterator<String> it2 = widgetsOverride.iterator();
                        while (it2.hasNext()) {
                            String widgetOverrideName = it2.next();
                            CLElement value = constraintSet.get(widgetOverrideName);
                            if (value instanceof CLObject) {
                                override(baseJson, widgetOverrideName, (CLObject) value);
                            }
                        }
                        scene.setConstraintSetContent(csName, baseJson.toJSON());
                        added = true;
                    }
                }
            }
            if (!added) {
                scene.setConstraintSetContent(csName, constraintSet.toJSON());
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:29:0x006d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void override(androidx.constraintlayout.core.parser.CLObject r8, java.lang.String r9, androidx.constraintlayout.core.parser.CLObject r10) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            boolean r0 = r8.has(r9)
            if (r0 != 0) goto Lb
            r8.put(r9, r10)
            goto Led
        Lb:
            androidx.constraintlayout.core.parser.CLObject r0 = r8.getObject(r9)
            java.util.ArrayList r1 = r10.names()
            java.util.Iterator r2 = r1.iterator()
        L17:
            boolean r3 = r2.hasNext()
            if (r3 == 0) goto Led
            java.lang.Object r3 = r2.next()
            java.lang.String r3 = (java.lang.String) r3
            java.lang.String r4 = "clear"
            boolean r5 = r3.equals(r4)
            if (r5 != 0) goto L33
            androidx.constraintlayout.core.parser.CLElement r4 = r10.get(r3)
            r0.put(r3, r4)
            goto L17
        L33:
            androidx.constraintlayout.core.parser.CLArray r4 = r10.getArray(r4)
            r5 = 0
        L38:
            int r6 = r4.size()
            if (r5 >= r6) goto Leb
            java.lang.String r6 = r4.getStringOrNull(r5)
            if (r6 != 0) goto L46
            goto Le7
        L46:
            int r7 = r6.hashCode()
            switch(r7) {
                case -1727069561: goto L62;
                case -1606703562: goto L58;
                case 414334925: goto L4e;
                default: goto L4d;
            }
        L4d:
            goto L6d
        L4e:
            java.lang.String r7 = "dimensions"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L4d
            r7 = 0
            goto L6e
        L58:
            java.lang.String r7 = "constraints"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L4d
            r7 = 1
            goto L6e
        L62:
            java.lang.String r7 = "transforms"
            boolean r7 = r6.equals(r7)
            if (r7 == 0) goto L4d
            r7 = 2
            goto L6e
        L6d:
            r7 = -1
        L6e:
            switch(r7) {
                case 0: goto Ldb;
                case 1: goto Lb0;
                case 2: goto L75;
                default: goto L71;
            }
        L71:
            r0.remove(r6)
            goto Le7
        L75:
            java.lang.String r7 = "visibility"
            r0.remove(r7)
            java.lang.String r7 = "alpha"
            r0.remove(r7)
            java.lang.String r7 = "pivotX"
            r0.remove(r7)
            java.lang.String r7 = "pivotY"
            r0.remove(r7)
            java.lang.String r7 = "rotationX"
            r0.remove(r7)
            java.lang.String r7 = "rotationY"
            r0.remove(r7)
            java.lang.String r7 = "rotationZ"
            r0.remove(r7)
            java.lang.String r7 = "scaleX"
            r0.remove(r7)
            java.lang.String r7 = "scaleY"
            r0.remove(r7)
            java.lang.String r7 = "translationX"
            r0.remove(r7)
            java.lang.String r7 = "translationY"
            r0.remove(r7)
            goto Le7
        Lb0:
            java.lang.String r7 = "start"
            r0.remove(r7)
            java.lang.String r7 = "end"
            r0.remove(r7)
            java.lang.String r7 = "top"
            r0.remove(r7)
            java.lang.String r7 = "bottom"
            r0.remove(r7)
            java.lang.String r7 = "baseline"
            r0.remove(r7)
            java.lang.String r7 = "center"
            r0.remove(r7)
            java.lang.String r7 = "centerHorizontally"
            r0.remove(r7)
            java.lang.String r7 = "centerVertically"
            r0.remove(r7)
            goto Le7
        Ldb:
            java.lang.String r7 = "width"
            r0.remove(r7)
            java.lang.String r7 = "height"
            r0.remove(r7)
        Le7:
            int r5 = r5 + 1
            goto L38
        Leb:
            goto L17
        Led:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.override(androidx.constraintlayout.core.parser.CLObject, java.lang.String, androidx.constraintlayout.core.parser.CLObject):void");
    }

    static void parseTransitions(CoreMotionScene scene, CLObject json) throws CLParsingException {
        ArrayList<String> elements = json.names();
        if (elements == null) {
            return;
        }
        Iterator<String> it = elements.iterator();
        while (it.hasNext()) {
            String elementName = it.next();
            scene.setTransitionContent(elementName, json.getObject(elementName).toJSON());
        }
    }

    static void parseHeader(CoreMotionScene scene, CLObject json) {
        String name = json.getStringOrNull("export");
        if (name != null) {
            scene.setDebugName(name);
        }
    }

    public static void parseJSON(String content, State state, LayoutVariables layoutVariables) throws CLParsingException {
        try {
            CLObject json = CLParser.parse(content);
            populateState(json, state, layoutVariables);
        } catch (CLParsingException e) {
            System.err.println("Error parsing JSON " + e);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00eb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void populateState(androidx.constraintlayout.core.parser.CLObject r10, androidx.constraintlayout.core.state.State r11, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r12) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 396
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.populateState(androidx.constraintlayout.core.parser.CLObject, androidx.constraintlayout.core.state.State, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables):void");
    }

    private static void parseVariables(State state, LayoutVariables layoutVariables, CLObject json) throws CLParsingException {
        ArrayList<String> elements = json.names();
        if (elements == null) {
            return;
        }
        Iterator<String> it = elements.iterator();
        while (it.hasNext()) {
            String elementName = it.next();
            CLElement element = json.get(elementName);
            if (element instanceof CLNumber) {
                layoutVariables.put(elementName, element.getInt());
            } else if (element instanceof CLObject) {
                CLObject obj = (CLObject) element;
                if (!obj.has(TypedValues.TransitionType.S_FROM) || !obj.has(TypedValues.TransitionType.S_TO)) {
                    if (obj.has(TypedValues.TransitionType.S_FROM) && obj.has("step")) {
                        float start = layoutVariables.get(obj.get(TypedValues.TransitionType.S_FROM));
                        float increment = layoutVariables.get(obj.get("step"));
                        layoutVariables.put(elementName, start, increment);
                    } else if (obj.has("ids")) {
                        CLArray ids = obj.getArray("ids");
                        ArrayList<String> arrayIds = new ArrayList<>();
                        for (int i = 0; i < ids.size(); i++) {
                            arrayIds.add(ids.getString(i));
                        }
                        layoutVariables.put(elementName, arrayIds);
                    } else if (obj.has("tag")) {
                        layoutVariables.put(elementName, state.getIdsForTag(obj.getString("tag")));
                    }
                } else {
                    float from = layoutVariables.get(obj.get(TypedValues.TransitionType.S_FROM));
                    float to = layoutVariables.get(obj.get(TypedValues.TransitionType.S_TO));
                    String prefix = obj.getStringOrNull("prefix");
                    String postfix = obj.getStringOrNull("postfix");
                    layoutVariables.put(elementName, from, to, 1.0f, prefix, postfix);
                }
            }
        }
    }

    public static void parseDesignElementsJSON(String content, ArrayList<DesignElement> list) throws CLParsingException {
        char c;
        CLObject json = CLParser.parse(content);
        ArrayList<String> elements = json.names();
        if (elements != null && 0 < elements.size()) {
            String elementName = elements.get(0);
            CLElement element = json.get(elementName);
            int i = 0;
            switch (elementName.hashCode()) {
                case 2043588062:
                    if (elementName.equals("Design")) {
                        c = 0;
                        break;
                    }
                default:
                    c = 65535;
                    break;
            }
            switch (c) {
                case 0:
                    if (element instanceof CLObject) {
                        CLObject obj = (CLObject) element;
                        ArrayList<String> elements2 = obj.names();
                        int j = 0;
                        while (j < elements2.size()) {
                            String designElementName = elements2.get(j);
                            CLObject designElement = (CLObject) ((CLObject) element).get(designElementName);
                            System.out.printf("element found " + designElementName + "", new Object[i]);
                            String type = designElement.getStringOrNull("type");
                            if (type != null) {
                                HashMap<String, String> parameters = new HashMap<>();
                                int size = designElement.size();
                                for (int k = 0; k < size; k++) {
                                    CLKey key = (CLKey) designElement.get(j);
                                    String paramName = key.content();
                                    String paramValue = key.getValue().content();
                                    if (paramValue != null) {
                                        parameters.put(paramName, paramValue);
                                    }
                                }
                                list.add(new DesignElement(elementName, type, parameters));
                            }
                            j++;
                            i = 0;
                        }
                        break;
                    }
                    break;
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0050  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void parseHelpers(androidx.constraintlayout.core.state.State r7, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r8, androidx.constraintlayout.core.parser.CLArray r9) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            r0 = 0
        L1:
            int r1 = r9.size()
            if (r0 >= r1) goto L68
            androidx.constraintlayout.core.parser.CLElement r1 = r9.get(r0)
            boolean r2 = r1 instanceof androidx.constraintlayout.core.parser.CLArray
            if (r2 == 0) goto L65
            r2 = r1
            androidx.constraintlayout.core.parser.CLArray r2 = (androidx.constraintlayout.core.parser.CLArray) r2
            int r3 = r2.size()
            r4 = 1
            if (r3 <= r4) goto L65
            r3 = 0
            java.lang.String r5 = r2.getString(r3)
            int r6 = r5.hashCode()
            switch(r6) {
                case -1785507558: goto L45;
                case -1252464839: goto L3b;
                case -851656725: goto L30;
                case 965681512: goto L26;
                default: goto L25;
            }
        L25:
            goto L50
        L26:
            java.lang.String r6 = "hGuideline"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L25
            r5 = 2
            goto L51
        L30:
            java.lang.String r6 = "vChain"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L25
            r5 = r4
            goto L51
        L3b:
            java.lang.String r6 = "hChain"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L25
            r5 = r3
            goto L51
        L45:
            java.lang.String r6 = "vGuideline"
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L25
            r5 = 3
            goto L51
        L50:
            r5 = -1
        L51:
            switch(r5) {
                case 0: goto L61;
                case 1: goto L5d;
                case 2: goto L59;
                case 3: goto L55;
                default: goto L54;
            }
        L54:
            goto L65
        L55:
            parseGuideline(r4, r7, r2)
            goto L65
        L59:
            parseGuideline(r3, r7, r2)
            goto L65
        L5d:
            parseChain(r4, r7, r8, r2)
            goto L65
        L61:
            parseChain(r3, r7, r8, r2)
        L65:
            int r0 = r0 + 1
            goto L1
        L68:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseHelpers(androidx.constraintlayout.core.state.State, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables, androidx.constraintlayout.core.parser.CLArray):void");
    }

    static void parseGenerate(State state, LayoutVariables layoutVariables, CLObject json) throws CLParsingException {
        ArrayList<String> elements = json.names();
        if (elements == null) {
            return;
        }
        Iterator<String> it = elements.iterator();
        while (it.hasNext()) {
            String elementName = it.next();
            CLElement element = json.get(elementName);
            ArrayList<String> arrayIds = layoutVariables.getList(elementName);
            if (arrayIds != null && (element instanceof CLObject)) {
                Iterator<String> it2 = arrayIds.iterator();
                while (it2.hasNext()) {
                    String id = it2.next();
                    parseWidget(state, layoutVariables, id, (CLObject) element);
                }
            }
        }
    }

    static void parseChain(int orientation, State state, LayoutVariables margins, CLArray helper) throws CLParsingException {
        boolean z;
        String styleValue;
        ChainReference chain = orientation == 0 ? state.horizontalChain() : state.verticalChain();
        CLElement refs = helper.get(1);
        if ((refs instanceof CLArray) && ((CLArray) refs).size() >= 1) {
            for (int i = 0; i < ((CLArray) refs).size(); i++) {
                chain.add(((CLArray) refs).getString(i));
            }
            int i2 = helper.size();
            if (i2 > 2) {
                CLElement params = helper.get(2);
                if (!(params instanceof CLObject)) {
                    return;
                }
                CLObject obj = (CLObject) params;
                ArrayList<String> constraints = obj.names();
                Iterator<String> it = constraints.iterator();
                while (it.hasNext()) {
                    String constraintName = it.next();
                    switch (constraintName.hashCode()) {
                        case 109780401:
                            if (constraintName.equals("style")) {
                                z = false;
                                break;
                            }
                        default:
                            z = -1;
                            break;
                    }
                    switch (z) {
                        case false:
                            CLElement styleObject = ((CLObject) params).get(constraintName);
                            if ((styleObject instanceof CLArray) && ((CLArray) styleObject).size() > 1) {
                                styleValue = ((CLArray) styleObject).getString(0);
                                float biasValue = ((CLArray) styleObject).getFloat(1);
                                chain.bias(biasValue);
                            } else {
                                styleValue = styleObject.content();
                            }
                            switch (styleValue) {
                                case "packed":
                                    chain.style(State.Chain.PACKED);
                                    break;
                                case "spread_inside":
                                    chain.style(State.Chain.SPREAD_INSIDE);
                                    break;
                                default:
                                    chain.style(State.Chain.SPREAD);
                                    break;
                            }
                            break;
                        default:
                            parseConstraint(state, margins, (CLObject) params, chain, constraintName);
                            break;
                    }
                }
            }
        }
    }

    private static float toPix(State state, float dp) {
        return state.getDpToPixel().toPixels(dp);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0092  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void parseChainType(java.lang.String r24, androidx.constraintlayout.core.state.State r25, java.lang.String r26, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r27, androidx.constraintlayout.core.parser.CLObject r28) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 632
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseChainType(java.lang.String, androidx.constraintlayout.core.state.State, java.lang.String, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables, androidx.constraintlayout.core.parser.CLObject):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00af  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void parseGridType(java.lang.String r16, androidx.constraintlayout.core.state.State r17, java.lang.String r18, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r19, androidx.constraintlayout.core.parser.CLObject r20) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 712
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseGridType(java.lang.String, androidx.constraintlayout.core.state.State, java.lang.String, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables, androidx.constraintlayout.core.parser.CLObject):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00cb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void parseFlowType(java.lang.String r19, androidx.constraintlayout.core.state.State r20, java.lang.String r21, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r22, androidx.constraintlayout.core.parser.CLObject r23) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 1408
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseFlowType(java.lang.String, androidx.constraintlayout.core.state.State, java.lang.String, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables, androidx.constraintlayout.core.parser.CLObject):void");
    }

    static void parseGuideline(int orientation, State state, CLArray helper) throws CLParsingException {
        String guidelineId;
        CLElement params = helper.get(1);
        if ((params instanceof CLObject) && (guidelineId = ((CLObject) params).getStringOrNull("id")) != null) {
            parseGuidelineParams(orientation, state, guidelineId, (CLObject) params);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:36:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00df  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void parseGuidelineParams(int r21, androidx.constraintlayout.core.state.State r22, java.lang.String r23, androidx.constraintlayout.core.parser.CLObject r24) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 454
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseGuidelineParams(int, androidx.constraintlayout.core.state.State, java.lang.String, androidx.constraintlayout.core.parser.CLObject):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00d6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void parseBarrier(androidx.constraintlayout.core.state.State r11, java.lang.String r12, androidx.constraintlayout.core.parser.CLObject r13) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 342
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseBarrier(androidx.constraintlayout.core.state.State, java.lang.String, androidx.constraintlayout.core.parser.CLObject):void");
    }

    static void parseWidget(State state, LayoutVariables layoutVariables, String elementName, CLObject element) throws CLParsingException {
        ConstraintReference reference = state.constraints(elementName);
        parseWidget(state, layoutVariables, reference, element);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:103:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0125  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void applyAttribute(androidx.constraintlayout.core.state.State r8, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r9, androidx.constraintlayout.core.state.ConstraintReference r10, androidx.constraintlayout.core.parser.CLObject r11, java.lang.String r12) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 904
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.applyAttribute(androidx.constraintlayout.core.state.State, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables, androidx.constraintlayout.core.state.ConstraintReference, androidx.constraintlayout.core.parser.CLObject, java.lang.String):void");
    }

    static void parseWidget(State state, LayoutVariables layoutVariables, ConstraintReference reference, CLObject element) throws CLParsingException {
        if (reference.getWidth() == null) {
            reference.setWidth(Dimension.createWrap());
        }
        if (reference.getHeight() == null) {
            reference.setHeight(Dimension.createWrap());
        }
        ArrayList<String> constraints = element.names();
        if (constraints == null) {
            return;
        }
        Iterator<String> it = constraints.iterator();
        while (it.hasNext()) {
            String constraintName = it.next();
            applyAttribute(state, layoutVariables, reference, element, constraintName);
        }
    }

    static void parseCustomProperties(CLObject element, ConstraintReference reference, String constraintName) throws CLParsingException {
        ArrayList<String> properties;
        CLObject json = element.getObjectOrNull(constraintName);
        if (json == null || (properties = json.names()) == null) {
            return;
        }
        Iterator<String> it = properties.iterator();
        while (it.hasNext()) {
            String property = it.next();
            CLElement value = json.get(property);
            if (value instanceof CLNumber) {
                reference.addCustomFloat(property, value.getFloat());
            } else if (value instanceof CLString) {
                long it2 = parseColorString(value.content());
                if (it2 != -1) {
                    reference.addCustomColor(property, (int) it2);
                }
            }
        }
    }

    private static int indexOf(String val, String... types) {
        for (int i = 0; i < types.length; i++) {
            if (types[i].equals(val)) {
                return i;
            }
        }
        return -1;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0065  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void parseMotionProperties(androidx.constraintlayout.core.parser.CLElement r14, androidx.constraintlayout.core.state.ConstraintReference r15) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseMotionProperties(androidx.constraintlayout.core.parser.CLElement, androidx.constraintlayout.core.state.ConstraintReference):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:106:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0218  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x02a2  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0174  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void parseConstraint(androidx.constraintlayout.core.state.State r25, androidx.constraintlayout.core.state.ConstraintSetParser.LayoutVariables r26, androidx.constraintlayout.core.parser.CLObject r27, androidx.constraintlayout.core.state.ConstraintReference r28, java.lang.String r29) throws androidx.constraintlayout.core.parser.CLParsingException {
        /*
            Method dump skipped, instructions count: 920
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseConstraint(androidx.constraintlayout.core.state.State, androidx.constraintlayout.core.state.ConstraintSetParser$LayoutVariables, androidx.constraintlayout.core.parser.CLObject, androidx.constraintlayout.core.state.ConstraintReference, java.lang.String):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0037  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static androidx.constraintlayout.core.state.Dimension parseDimensionMode(java.lang.String r5) {
        /*
            r0 = 0
            androidx.constraintlayout.core.state.Dimension r1 = androidx.constraintlayout.core.state.Dimension.createFixed(r0)
            int r2 = r5.hashCode()
            switch(r2) {
                case -1460244870: goto L2d;
                case -995424086: goto L23;
                case -895684237: goto L18;
                case 3657802: goto Ld;
                default: goto Lc;
            }
        Lc:
            goto L37
        Ld:
            java.lang.String r2 = "wrap"
            boolean r2 = r5.equals(r2)
            if (r2 == 0) goto Lc
            r2 = r0
            goto L38
        L18:
            java.lang.String r2 = "spread"
            boolean r2 = r5.equals(r2)
            if (r2 == 0) goto Lc
            r2 = 2
            goto L38
        L23:
            java.lang.String r2 = "parent"
            boolean r2 = r5.equals(r2)
            if (r2 == 0) goto Lc
            r2 = 3
            goto L38
        L2d:
            java.lang.String r2 = "preferWrap"
            boolean r2 = r5.equals(r2)
            if (r2 == 0) goto Lc
            r2 = 1
            goto L38
        L37:
            r2 = -1
        L38:
            switch(r2) {
                case 0: goto L75;
                case 1: goto L6e;
                case 2: goto L67;
                case 3: goto L62;
                default: goto L3b;
            }
        L3b:
            java.lang.String r2 = "%"
            boolean r2 = r5.endsWith(r2)
            if (r2 == 0) goto L7a
        L44:
            r2 = 37
            int r2 = r5.indexOf(r2)
            java.lang.String r2 = r5.substring(r0, r2)
            float r3 = java.lang.Float.parseFloat(r2)
            r4 = 1120403456(0x42c80000, float:100.0)
            float r3 = r3 / r4
            java.lang.Integer r4 = java.lang.Integer.valueOf(r0)
            androidx.constraintlayout.core.state.Dimension r4 = androidx.constraintlayout.core.state.Dimension.createPercent(r4, r3)
            androidx.constraintlayout.core.state.Dimension r1 = r4.suggested(r0)
            goto L8d
        L62:
            androidx.constraintlayout.core.state.Dimension r1 = androidx.constraintlayout.core.state.Dimension.createParent()
            goto L8e
        L67:
            java.lang.Object r0 = androidx.constraintlayout.core.state.Dimension.SPREAD_DIMENSION
            androidx.constraintlayout.core.state.Dimension r1 = androidx.constraintlayout.core.state.Dimension.createSuggested(r0)
            goto L8e
        L6e:
            java.lang.Object r0 = androidx.constraintlayout.core.state.Dimension.WRAP_DIMENSION
            androidx.constraintlayout.core.state.Dimension r1 = androidx.constraintlayout.core.state.Dimension.createSuggested(r0)
            goto L8e
        L75:
            androidx.constraintlayout.core.state.Dimension r1 = androidx.constraintlayout.core.state.Dimension.createWrap()
            goto L8e
        L7a:
            java.lang.String r0 = ":"
            boolean r0 = r5.contains(r0)
            if (r0 == 0) goto L8d
            androidx.constraintlayout.core.state.Dimension r0 = androidx.constraintlayout.core.state.Dimension.createRatio(r5)
            java.lang.Object r2 = androidx.constraintlayout.core.state.Dimension.SPREAD_DIMENSION
            androidx.constraintlayout.core.state.Dimension r1 = r0.suggested(r2)
            goto L8e
        L8d:
        L8e:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.state.ConstraintSetParser.parseDimensionMode(java.lang.String):androidx.constraintlayout.core.state.Dimension");
    }

    static Dimension parseDimension(CLObject element, String constraintName, State state, CorePixelDp dpToPixels) throws CLParsingException {
        CLElement dimensionElement = element.get(constraintName);
        Dimension dimension = Dimension.createFixed(0);
        if (dimensionElement instanceof CLString) {
            return parseDimensionMode(dimensionElement.content());
        }
        if (dimensionElement instanceof CLNumber) {
            return Dimension.createFixed(state.convertDimension(Float.valueOf(dpToPixels.toPixels(element.getFloat(constraintName)))));
        }
        if (dimensionElement instanceof CLObject) {
            CLObject obj = (CLObject) dimensionElement;
            String mode = obj.getStringOrNull("value");
            if (mode != null) {
                dimension = parseDimensionMode(mode);
            }
            CLElement minEl = obj.getOrNull("min");
            if (minEl != null) {
                if (minEl instanceof CLNumber) {
                    float min = ((CLNumber) minEl).getFloat();
                    dimension.min(state.convertDimension(Float.valueOf(dpToPixels.toPixels(min))));
                } else if (minEl instanceof CLString) {
                    dimension.min(Dimension.WRAP_DIMENSION);
                }
            }
            CLElement maxEl = obj.getOrNull("max");
            if (maxEl != null) {
                if (maxEl instanceof CLNumber) {
                    float max = ((CLNumber) maxEl).getFloat();
                    dimension.max(state.convertDimension(Float.valueOf(dpToPixels.toPixels(max))));
                    return dimension;
                }
                if (maxEl instanceof CLString) {
                    dimension.max(Dimension.WRAP_DIMENSION);
                    return dimension;
                }
                return dimension;
            }
            return dimension;
        }
        return dimension;
    }

    static long parseColorString(String value) {
        if (value.startsWith("#")) {
            String str = value.substring(1);
            if (str.length() == 6) {
                str = "FF" + str;
            }
            return Long.parseLong(str, 16);
        }
        return -1L;
    }

    static String lookForType(CLObject element) throws CLParsingException {
        ArrayList<String> constraints = element.names();
        Iterator<String> it = constraints.iterator();
        while (it.hasNext()) {
            String constraintName = it.next();
            if (constraintName.equals("type")) {
                return element.getString("type");
            }
        }
        return null;
    }
}
