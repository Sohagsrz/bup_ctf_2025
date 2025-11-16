package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.util.Xml;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes.dex */
public class StateSet {
    private static final boolean DEBUG = false;
    public static final String TAG = "ConstraintLayoutStates";
    int mDefaultState = -1;
    int mCurrentStateId = -1;
    int mCurrentConstraintNumber = -1;
    private SparseArray<State> mStateList = new SparseArray<>();
    private ConstraintsChangedListener mConstraintsChangedListener = null;

    public StateSet(Context context, XmlPullParser parser) throws XmlPullParserException, IOException {
        load(context, parser);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x004f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void load(android.content.Context r12, org.xmlpull.v1.XmlPullParser r13) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException {
        /*
            r11 = this;
            java.lang.String r0 = "Error parsing XML resource"
            java.lang.String r1 = "ConstraintLayoutStates"
            android.util.AttributeSet r2 = android.util.Xml.asAttributeSet(r13)
            int[] r3 = androidx.constraintlayout.widget.R.styleable.StateSet
            android.content.res.TypedArray r3 = r12.obtainStyledAttributes(r2, r3)
            int r4 = r3.getIndexCount()
            r5 = 0
        L13:
            if (r5 >= r4) goto L28
            int r6 = r3.getIndex(r5)
            int r7 = androidx.constraintlayout.widget.R.styleable.StateSet_defaultState
            if (r6 != r7) goto L25
            int r7 = r11.mDefaultState
            int r7 = r3.getResourceId(r6, r7)
            r11.mDefaultState = r7
        L25:
            int r5 = r5 + 1
            goto L13
        L28:
            r3.recycle()
            r5 = 0
            int r6 = r13.getEventType()     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
        L30:
            r7 = 1
            if (r6 == r7) goto L9d
            java.lang.String r8 = "StateSet"
            switch(r6) {
                case 0: goto L96;
                case 1: goto L38;
                case 2: goto L44;
                case 3: goto L39;
                case 4: goto L96;
                default: goto L38;
            }
        L38:
            goto L97
        L39:
            java.lang.String r7 = r13.getName()     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            boolean r7 = r8.equals(r7)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            if (r7 == 0) goto L97
            return
        L44:
            java.lang.String r9 = r13.getName()     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            int r10 = r9.hashCode()     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            switch(r10) {
                case 80204913: goto L6b;
                case 1301459538: goto L61;
                case 1382829617: goto L5a;
                case 1901439077: goto L50;
                default: goto L4f;
            }     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
        L4f:
            goto L75
        L50:
            java.lang.String r7 = "Variant"
            boolean r7 = r9.equals(r7)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            if (r7 == 0) goto L4f
            r7 = 3
            goto L76
        L5a:
            boolean r8 = r9.equals(r8)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            if (r8 == 0) goto L4f
            goto L76
        L61:
            java.lang.String r7 = "LayoutDescription"
            boolean r7 = r9.equals(r7)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            if (r7 == 0) goto L4f
            r7 = 0
            goto L76
        L6b:
            java.lang.String r7 = "State"
            boolean r7 = r9.equals(r7)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            if (r7 == 0) goto L4f
            r7 = 2
            goto L76
        L75:
            r7 = -1
        L76:
            switch(r7) {
                case 0: goto L94;
                case 1: goto L93;
                case 2: goto L85;
                case 3: goto L7a;
                default: goto L79;
            }     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
        L79:
            goto L95
        L7a:
            androidx.constraintlayout.widget.StateSet$Variant r7 = new androidx.constraintlayout.widget.StateSet$Variant     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            r7.<init>(r12, r13)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            if (r5 == 0) goto L95
            r5.add(r7)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            goto L95
        L85:
            androidx.constraintlayout.widget.StateSet$State r7 = new androidx.constraintlayout.widget.StateSet$State     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            r7.<init>(r12, r13)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            r5 = r7
            android.util.SparseArray<androidx.constraintlayout.widget.StateSet$State> r7 = r11.mStateList     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            int r8 = r5.mId     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            r7.put(r8, r5)     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            goto L95
        L93:
            goto L95
        L94:
        L95:
            goto L97
        L96:
        L97:
            int r7 = r13.next()     // Catch: java.io.IOException -> L9e org.xmlpull.v1.XmlPullParserException -> La3
            r6 = r7
            goto L30
        L9d:
            goto La7
        L9e:
            r5 = move-exception
            android.util.Log.e(r1, r0, r5)
            goto La8
        La3:
            r5 = move-exception
            android.util.Log.e(r1, r0, r5)
        La7:
        La8:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.StateSet.load(android.content.Context, org.xmlpull.v1.XmlPullParser):void");
    }

    public boolean needsToChange(int id, float width, float height) {
        if (this.mCurrentStateId != id) {
            return true;
        }
        SparseArray<State> sparseArray = this.mStateList;
        State state = id == -1 ? sparseArray.valueAt(0) : sparseArray.get(this.mCurrentStateId);
        return (this.mCurrentConstraintNumber == -1 || !state.mVariants.get(this.mCurrentConstraintNumber).match(width, height)) && this.mCurrentConstraintNumber != state.findMatch(width, height);
    }

    public void setOnConstraintsChanged(ConstraintsChangedListener constraintsChangedListener) {
        this.mConstraintsChangedListener = constraintsChangedListener;
    }

    public int stateGetConstraintID(int id, int width, int height) {
        return updateConstraints(-1, id, width, height);
    }

    public int convertToConstraintSet(int currentConstrainSettId, int stateId, float width, float height) {
        State state = this.mStateList.get(stateId);
        if (state == null) {
            return stateId;
        }
        if (width == -1.0f || height == -1.0f) {
            if (state.mConstraintID == currentConstrainSettId) {
                return currentConstrainSettId;
            }
            Iterator<Variant> it = state.mVariants.iterator();
            while (it.hasNext()) {
                if (currentConstrainSettId == it.next().mConstraintID) {
                    return currentConstrainSettId;
                }
            }
            return state.mConstraintID;
        }
        Variant match = null;
        Iterator<Variant> it2 = state.mVariants.iterator();
        while (it2.hasNext()) {
            Variant mVariant = it2.next();
            if (mVariant.match(width, height)) {
                if (currentConstrainSettId == mVariant.mConstraintID) {
                    return currentConstrainSettId;
                }
                match = mVariant;
            }
        }
        if (match != null) {
            return match.mConstraintID;
        }
        return state.mConstraintID;
    }

    public int updateConstraints(int currentId, int id, float width, float height) {
        State state;
        int match;
        if (currentId == id) {
            if (id == -1) {
                state = this.mStateList.valueAt(0);
            } else {
                state = this.mStateList.get(this.mCurrentStateId);
            }
            if (state == null) {
                return -1;
            }
            if ((this.mCurrentConstraintNumber == -1 || !state.mVariants.get(currentId).match(width, height)) && currentId != (match = state.findMatch(width, height))) {
                return match == -1 ? state.mConstraintID : state.mVariants.get(match).mConstraintID;
            }
            return currentId;
        }
        State state2 = this.mStateList.get(id);
        if (state2 == null) {
            return -1;
        }
        int match2 = state2.findMatch(width, height);
        return match2 == -1 ? state2.mConstraintID : state2.mVariants.get(match2).mConstraintID;
    }

    static class State {
        int mConstraintID;
        int mId;
        boolean mIsLayout;
        ArrayList<Variant> mVariants = new ArrayList<>();

        State(Context context, XmlPullParser parser) throws Resources.NotFoundException {
            this.mConstraintID = -1;
            this.mIsLayout = false;
            AttributeSet attrs = Xml.asAttributeSet(parser);
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.State);
            int count = a.getIndexCount();
            for (int i = 0; i < count; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.State_android_id) {
                    this.mId = a.getResourceId(attr, this.mId);
                } else if (attr == R.styleable.State_constraints) {
                    this.mConstraintID = a.getResourceId(attr, this.mConstraintID);
                    String type = context.getResources().getResourceTypeName(this.mConstraintID);
                    context.getResources().getResourceName(this.mConstraintID);
                    if ("layout".equals(type)) {
                        this.mIsLayout = true;
                    }
                }
            }
            a.recycle();
        }

        void add(Variant size) {
            this.mVariants.add(size);
        }

        public int findMatch(float width, float height) {
            for (int i = 0; i < this.mVariants.size(); i++) {
                if (this.mVariants.get(i).match(width, height)) {
                    return i;
                }
            }
            return -1;
        }
    }

    static class Variant {
        int mConstraintID;
        int mId;
        boolean mIsLayout;
        float mMaxHeight;
        float mMaxWidth;
        float mMinHeight;
        float mMinWidth;

        Variant(Context context, XmlPullParser parser) throws Resources.NotFoundException {
            this.mMinWidth = Float.NaN;
            this.mMinHeight = Float.NaN;
            this.mMaxWidth = Float.NaN;
            this.mMaxHeight = Float.NaN;
            this.mConstraintID = -1;
            this.mIsLayout = false;
            AttributeSet attrs = Xml.asAttributeSet(parser);
            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.Variant);
            int count = a.getIndexCount();
            for (int i = 0; i < count; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.Variant_constraints) {
                    this.mConstraintID = a.getResourceId(attr, this.mConstraintID);
                    String type = context.getResources().getResourceTypeName(this.mConstraintID);
                    context.getResources().getResourceName(this.mConstraintID);
                    if ("layout".equals(type)) {
                        this.mIsLayout = true;
                    }
                } else if (attr == R.styleable.Variant_region_heightLessThan) {
                    this.mMaxHeight = a.getDimension(attr, this.mMaxHeight);
                } else if (attr == R.styleable.Variant_region_heightMoreThan) {
                    this.mMinHeight = a.getDimension(attr, this.mMinHeight);
                } else if (attr == R.styleable.Variant_region_widthLessThan) {
                    this.mMaxWidth = a.getDimension(attr, this.mMaxWidth);
                } else if (attr == R.styleable.Variant_region_widthMoreThan) {
                    this.mMinWidth = a.getDimension(attr, this.mMinWidth);
                } else {
                    Log.v("ConstraintLayoutStates", "Unknown tag");
                }
            }
            a.recycle();
        }

        boolean match(float widthDp, float heightDp) {
            if (!Float.isNaN(this.mMinWidth) && widthDp < this.mMinWidth) {
                return false;
            }
            if (!Float.isNaN(this.mMinHeight) && heightDp < this.mMinHeight) {
                return false;
            }
            if (Float.isNaN(this.mMaxWidth) || widthDp <= this.mMaxWidth) {
                return Float.isNaN(this.mMaxHeight) || heightDp <= this.mMaxHeight;
            }
            return false;
        }
    }
}
