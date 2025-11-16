package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.core.state.HelperReference;
import androidx.constraintlayout.core.state.State;
import androidx.constraintlayout.core.widgets.Flow;
import androidx.constraintlayout.core.widgets.HelperWidget;
import java.util.HashMap;

/* loaded from: classes.dex */
public class FlowReference extends HelperReference {
    protected float mFirstHorizontalBias;
    protected int mFirstHorizontalStyle;
    protected float mFirstVerticalBias;
    protected int mFirstVerticalStyle;
    protected Flow mFlow;
    protected int mHorizontalAlign;
    protected int mHorizontalGap;
    protected int mHorizontalStyle;
    protected float mLastHorizontalBias;
    protected int mLastHorizontalStyle;
    protected float mLastVerticalBias;
    protected int mLastVerticalStyle;
    protected HashMap<String, Float> mMapPostMargin;
    protected HashMap<String, Float> mMapPreMargin;
    protected HashMap<String, Float> mMapWeights;
    protected int mMaxElementsWrap;
    protected int mOrientation;
    protected int mPaddingBottom;
    protected int mPaddingLeft;
    protected int mPaddingRight;
    protected int mPaddingTop;
    protected int mVerticalAlign;
    protected int mVerticalGap;
    protected int mVerticalStyle;
    protected int mWrapMode;

    public FlowReference(State state, State.Helper type) {
        super(state, type);
        this.mWrapMode = 0;
        this.mVerticalStyle = -1;
        this.mFirstVerticalStyle = -1;
        this.mLastVerticalStyle = -1;
        this.mHorizontalStyle = -1;
        this.mFirstHorizontalStyle = -1;
        this.mLastHorizontalStyle = -1;
        this.mVerticalAlign = 2;
        this.mHorizontalAlign = 2;
        this.mVerticalGap = 0;
        this.mHorizontalGap = 0;
        this.mPaddingLeft = 0;
        this.mPaddingRight = 0;
        this.mPaddingTop = 0;
        this.mPaddingBottom = 0;
        this.mMaxElementsWrap = -1;
        this.mOrientation = 0;
        this.mFirstVerticalBias = 0.5f;
        this.mLastVerticalBias = 0.5f;
        this.mFirstHorizontalBias = 0.5f;
        this.mLastHorizontalBias = 0.5f;
        if (type == State.Helper.VERTICAL_FLOW) {
            this.mOrientation = 1;
        }
    }

    public void addFlowElement(String id, float weight, float preMargin, float postMargin) {
        super.add(id);
        if (!Float.isNaN(weight)) {
            if (this.mMapWeights == null) {
                this.mMapWeights = new HashMap<>();
            }
            this.mMapWeights.put(id, Float.valueOf(weight));
        }
        if (!Float.isNaN(preMargin)) {
            if (this.mMapPreMargin == null) {
                this.mMapPreMargin = new HashMap<>();
            }
            this.mMapPreMargin.put(id, Float.valueOf(preMargin));
        }
        if (!Float.isNaN(postMargin)) {
            if (this.mMapPostMargin == null) {
                this.mMapPostMargin = new HashMap<>();
            }
            this.mMapPostMargin.put(id, Float.valueOf(postMargin));
        }
    }

    protected float getWeight(String id) {
        if (this.mMapWeights != null && this.mMapWeights.containsKey(id)) {
            return this.mMapWeights.get(id).floatValue();
        }
        return -1.0f;
    }

    protected float getPostMargin(String id) {
        if (this.mMapPreMargin != null && this.mMapPreMargin.containsKey(id)) {
            return this.mMapPreMargin.get(id).floatValue();
        }
        return 0.0f;
    }

    protected float getPreMargin(String id) {
        if (this.mMapPostMargin != null && this.mMapPostMargin.containsKey(id)) {
            return this.mMapPostMargin.get(id).floatValue();
        }
        return 0.0f;
    }

    public int getWrapMode() {
        return this.mWrapMode;
    }

    public void setWrapMode(int wrap) {
        this.mWrapMode = wrap;
    }

    public int getPaddingLeft() {
        return this.mPaddingLeft;
    }

    public void setPaddingLeft(int padding) {
        this.mPaddingLeft = padding;
    }

    public int getPaddingTop() {
        return this.mPaddingTop;
    }

    public void setPaddingTop(int padding) {
        this.mPaddingTop = padding;
    }

    public int getPaddingRight() {
        return this.mPaddingRight;
    }

    public void setPaddingRight(int padding) {
        this.mPaddingRight = padding;
    }

    public int getPaddingBottom() {
        return this.mPaddingBottom;
    }

    public void setPaddingBottom(int padding) {
        this.mPaddingBottom = padding;
    }

    public int getVerticalStyle() {
        return this.mVerticalStyle;
    }

    public void setVerticalStyle(int verticalStyle) {
        this.mVerticalStyle = verticalStyle;
    }

    public int getFirstVerticalStyle() {
        return this.mFirstVerticalStyle;
    }

    public void setFirstVerticalStyle(int firstVerticalStyle) {
        this.mFirstVerticalStyle = firstVerticalStyle;
    }

    public int getLastVerticalStyle() {
        return this.mLastVerticalStyle;
    }

    public void setLastVerticalStyle(int lastVerticalStyle) {
        this.mLastVerticalStyle = lastVerticalStyle;
    }

    public int getHorizontalStyle() {
        return this.mHorizontalStyle;
    }

    public void setHorizontalStyle(int horizontalStyle) {
        this.mHorizontalStyle = horizontalStyle;
    }

    public int getFirstHorizontalStyle() {
        return this.mFirstHorizontalStyle;
    }

    public void setFirstHorizontalStyle(int firstHorizontalStyle) {
        this.mFirstHorizontalStyle = firstHorizontalStyle;
    }

    public int getLastHorizontalStyle() {
        return this.mLastHorizontalStyle;
    }

    public void setLastHorizontalStyle(int lastHorizontalStyle) {
        this.mLastHorizontalStyle = lastHorizontalStyle;
    }

    public int getVerticalAlign() {
        return this.mVerticalAlign;
    }

    public void setVerticalAlign(int verticalAlign) {
        this.mVerticalAlign = verticalAlign;
    }

    public int getHorizontalAlign() {
        return this.mHorizontalAlign;
    }

    public void setHorizontalAlign(int horizontalAlign) {
        this.mHorizontalAlign = horizontalAlign;
    }

    public int getVerticalGap() {
        return this.mVerticalGap;
    }

    public void setVerticalGap(int verticalGap) {
        this.mVerticalGap = verticalGap;
    }

    public int getHorizontalGap() {
        return this.mHorizontalGap;
    }

    public void setHorizontalGap(int horizontalGap) {
        this.mHorizontalGap = horizontalGap;
    }

    public int getMaxElementsWrap() {
        return this.mMaxElementsWrap;
    }

    public void setMaxElementsWrap(int maxElementsWrap) {
        this.mMaxElementsWrap = maxElementsWrap;
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    public void setOrientation(int mOrientation) {
        this.mOrientation = mOrientation;
    }

    public float getVerticalBias() {
        return this.mVerticalBias;
    }

    public float getFirstVerticalBias() {
        return this.mFirstVerticalBias;
    }

    public void setFirstVerticalBias(float firstVerticalBias) {
        this.mFirstVerticalBias = firstVerticalBias;
    }

    public float getLastVerticalBias() {
        return this.mLastVerticalBias;
    }

    public void setLastVerticalBias(float lastVerticalBias) {
        this.mLastVerticalBias = lastVerticalBias;
    }

    public float getHorizontalBias() {
        return this.mHorizontalBias;
    }

    public float getFirstHorizontalBias() {
        return this.mFirstHorizontalBias;
    }

    public void setFirstHorizontalBias(float firstHorizontalBias) {
        this.mFirstHorizontalBias = firstHorizontalBias;
    }

    public float getLastHorizontalBias() {
        return this.mLastHorizontalBias;
    }

    public void setLastHorizontalBias(float lastHorizontalBias) {
        this.mLastHorizontalBias = lastHorizontalBias;
    }

    @Override // androidx.constraintlayout.core.state.HelperReference
    public HelperWidget getHelperWidget() {
        if (this.mFlow == null) {
            this.mFlow = new Flow();
        }
        return this.mFlow;
    }

    @Override // androidx.constraintlayout.core.state.HelperReference
    public void setHelperWidget(HelperWidget widget) {
        if (widget instanceof Flow) {
            this.mFlow = (Flow) widget;
        } else {
            this.mFlow = null;
        }
    }

    @Override // androidx.constraintlayout.core.state.HelperReference, androidx.constraintlayout.core.state.ConstraintReference, androidx.constraintlayout.core.state.Reference
    public void apply() {
        getHelperWidget();
        setConstraintWidget(this.mFlow);
        this.mFlow.setOrientation(this.mOrientation);
        this.mFlow.setWrapMode(this.mWrapMode);
        if (this.mMaxElementsWrap != -1) {
            this.mFlow.setMaxElementsWrap(this.mMaxElementsWrap);
        }
        if (this.mPaddingLeft != 0) {
            this.mFlow.setPaddingLeft(this.mPaddingLeft);
        }
        if (this.mPaddingTop != 0) {
            this.mFlow.setPaddingTop(this.mPaddingTop);
        }
        if (this.mPaddingRight != 0) {
            this.mFlow.setPaddingRight(this.mPaddingRight);
        }
        if (this.mPaddingBottom != 0) {
            this.mFlow.setPaddingBottom(this.mPaddingBottom);
        }
        if (this.mHorizontalGap != 0) {
            this.mFlow.setHorizontalGap(this.mHorizontalGap);
        }
        if (this.mVerticalGap != 0) {
            this.mFlow.setVerticalGap(this.mVerticalGap);
        }
        if (this.mHorizontalBias != 0.5f) {
            this.mFlow.setHorizontalBias(this.mHorizontalBias);
        }
        if (this.mFirstHorizontalBias != 0.5f) {
            this.mFlow.setFirstHorizontalBias(this.mFirstHorizontalBias);
        }
        if (this.mLastHorizontalBias != 0.5f) {
            this.mFlow.setLastHorizontalBias(this.mLastHorizontalBias);
        }
        if (this.mVerticalBias != 0.5f) {
            this.mFlow.setVerticalBias(this.mVerticalBias);
        }
        if (this.mFirstVerticalBias != 0.5f) {
            this.mFlow.setFirstVerticalBias(this.mFirstVerticalBias);
        }
        if (this.mLastVerticalBias != 0.5f) {
            this.mFlow.setLastVerticalBias(this.mLastVerticalBias);
        }
        if (this.mHorizontalAlign != 2) {
            this.mFlow.setHorizontalAlign(this.mHorizontalAlign);
        }
        if (this.mVerticalAlign != 2) {
            this.mFlow.setVerticalAlign(this.mVerticalAlign);
        }
        if (this.mVerticalStyle != -1) {
            this.mFlow.setVerticalStyle(this.mVerticalStyle);
        }
        if (this.mFirstVerticalStyle != -1) {
            this.mFlow.setFirstVerticalStyle(this.mFirstVerticalStyle);
        }
        if (this.mLastVerticalStyle != -1) {
            this.mFlow.setLastVerticalStyle(this.mLastVerticalStyle);
        }
        if (this.mHorizontalStyle != -1) {
            this.mFlow.setHorizontalStyle(this.mHorizontalStyle);
        }
        if (this.mFirstHorizontalStyle != -1) {
            this.mFlow.setFirstHorizontalStyle(this.mFirstHorizontalStyle);
        }
        if (this.mLastHorizontalStyle != -1) {
            this.mFlow.setLastHorizontalStyle(this.mLastHorizontalStyle);
        }
        applyBase();
    }
}
