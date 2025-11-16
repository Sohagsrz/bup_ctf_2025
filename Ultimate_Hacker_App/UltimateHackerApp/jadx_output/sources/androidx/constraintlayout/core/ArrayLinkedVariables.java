package androidx.constraintlayout.core;

import androidx.constraintlayout.core.ArrayRow;
import java.util.Arrays;

/* loaded from: classes.dex */
public class ArrayLinkedVariables implements ArrayRow.ArrayRowVariables {
    private static final boolean DEBUG = false;
    static final int NONE = -1;
    private static float sEpsilon = 0.001f;
    protected final Cache mCache;
    private final ArrayRow mRow;
    int mCurrentSize = 0;
    private int mRowSize = 8;
    private SolverVariable mCandidate = null;
    private int[] mArrayIndices = new int[this.mRowSize];
    private int[] mArrayNextIndices = new int[this.mRowSize];
    private float[] mArrayValues = new float[this.mRowSize];
    private int mHead = -1;
    private int mLast = -1;
    private boolean mDidFillOnce = false;

    ArrayLinkedVariables(ArrayRow arrayRow, Cache cache) {
        this.mRow = arrayRow;
        this.mCache = cache;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public final void put(SolverVariable variable, float value) {
        if (value == 0.0f) {
            remove(variable, true);
            return;
        }
        if (this.mHead == -1) {
            this.mHead = 0;
            this.mArrayValues[this.mHead] = value;
            this.mArrayIndices[this.mHead] = variable.id;
            this.mArrayNextIndices[this.mHead] = -1;
            variable.usageInRowCount++;
            variable.addToRow(this.mRow);
            this.mCurrentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
                if (this.mLast >= this.mArrayIndices.length) {
                    this.mDidFillOnce = true;
                    this.mLast = this.mArrayIndices.length - 1;
                    return;
                }
                return;
            }
            return;
        }
        int current = this.mHead;
        int previous = -1;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (this.mArrayIndices[current] == variable.id) {
                this.mArrayValues[current] = value;
                return;
            }
            if (this.mArrayIndices[current] < variable.id) {
                previous = current;
            }
            current = this.mArrayNextIndices[current];
        }
        int availableIndice = this.mLast + 1;
        if (this.mDidFillOnce) {
            if (this.mArrayIndices[this.mLast] == -1) {
                availableIndice = this.mLast;
            } else {
                availableIndice = this.mArrayIndices.length;
            }
        }
        if (availableIndice >= this.mArrayIndices.length && this.mCurrentSize < this.mArrayIndices.length) {
            int i = 0;
            while (true) {
                if (i >= this.mArrayIndices.length) {
                    break;
                }
                if (this.mArrayIndices[i] != -1) {
                    i++;
                } else {
                    availableIndice = i;
                    break;
                }
            }
        }
        if (availableIndice >= this.mArrayIndices.length) {
            availableIndice = this.mArrayIndices.length;
            this.mRowSize *= 2;
            this.mDidFillOnce = false;
            this.mLast = availableIndice - 1;
            this.mArrayValues = Arrays.copyOf(this.mArrayValues, this.mRowSize);
            this.mArrayIndices = Arrays.copyOf(this.mArrayIndices, this.mRowSize);
            this.mArrayNextIndices = Arrays.copyOf(this.mArrayNextIndices, this.mRowSize);
        }
        this.mArrayIndices[availableIndice] = variable.id;
        this.mArrayValues[availableIndice] = value;
        if (previous != -1) {
            this.mArrayNextIndices[availableIndice] = this.mArrayNextIndices[previous];
            this.mArrayNextIndices[previous] = availableIndice;
        } else {
            this.mArrayNextIndices[availableIndice] = this.mHead;
            this.mHead = availableIndice;
        }
        variable.usageInRowCount++;
        variable.addToRow(this.mRow);
        this.mCurrentSize++;
        if (!this.mDidFillOnce) {
            this.mLast++;
        }
        if (this.mCurrentSize >= this.mArrayIndices.length) {
            this.mDidFillOnce = true;
        }
        if (this.mLast >= this.mArrayIndices.length) {
            this.mDidFillOnce = true;
            this.mLast = this.mArrayIndices.length - 1;
        }
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public void add(SolverVariable variable, float value, boolean removeFromDefinition) {
        if (value > (-sEpsilon) && value < sEpsilon) {
            return;
        }
        if (this.mHead == -1) {
            this.mHead = 0;
            this.mArrayValues[this.mHead] = value;
            this.mArrayIndices[this.mHead] = variable.id;
            this.mArrayNextIndices[this.mHead] = -1;
            variable.usageInRowCount++;
            variable.addToRow(this.mRow);
            this.mCurrentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
                if (this.mLast >= this.mArrayIndices.length) {
                    this.mDidFillOnce = true;
                    this.mLast = this.mArrayIndices.length - 1;
                    return;
                }
                return;
            }
            return;
        }
        int current = this.mHead;
        int previous = -1;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            int idx = this.mArrayIndices[current];
            if (idx == variable.id) {
                float v = this.mArrayValues[current] + value;
                if (v > (-sEpsilon) && v < sEpsilon) {
                    v = 0.0f;
                }
                this.mArrayValues[current] = v;
                if (v == 0.0f) {
                    if (current == this.mHead) {
                        this.mHead = this.mArrayNextIndices[current];
                    } else {
                        this.mArrayNextIndices[previous] = this.mArrayNextIndices[current];
                    }
                    if (removeFromDefinition) {
                        variable.removeFromRow(this.mRow);
                    }
                    if (this.mDidFillOnce) {
                        this.mLast = current;
                    }
                    variable.usageInRowCount--;
                    this.mCurrentSize--;
                    return;
                }
                return;
            }
            if (this.mArrayIndices[current] < variable.id) {
                previous = current;
            }
            current = this.mArrayNextIndices[current];
        }
        int availableIndice = this.mLast + 1;
        if (this.mDidFillOnce) {
            if (this.mArrayIndices[this.mLast] == -1) {
                availableIndice = this.mLast;
            } else {
                availableIndice = this.mArrayIndices.length;
            }
        }
        if (availableIndice >= this.mArrayIndices.length && this.mCurrentSize < this.mArrayIndices.length) {
            int i = 0;
            while (true) {
                if (i >= this.mArrayIndices.length) {
                    break;
                }
                if (this.mArrayIndices[i] != -1) {
                    i++;
                } else {
                    availableIndice = i;
                    break;
                }
            }
        }
        if (availableIndice >= this.mArrayIndices.length) {
            availableIndice = this.mArrayIndices.length;
            this.mRowSize *= 2;
            this.mDidFillOnce = false;
            this.mLast = availableIndice - 1;
            this.mArrayValues = Arrays.copyOf(this.mArrayValues, this.mRowSize);
            this.mArrayIndices = Arrays.copyOf(this.mArrayIndices, this.mRowSize);
            this.mArrayNextIndices = Arrays.copyOf(this.mArrayNextIndices, this.mRowSize);
        }
        this.mArrayIndices[availableIndice] = variable.id;
        this.mArrayValues[availableIndice] = value;
        if (previous != -1) {
            this.mArrayNextIndices[availableIndice] = this.mArrayNextIndices[previous];
            this.mArrayNextIndices[previous] = availableIndice;
        } else {
            this.mArrayNextIndices[availableIndice] = this.mHead;
            this.mHead = availableIndice;
        }
        variable.usageInRowCount++;
        variable.addToRow(this.mRow);
        this.mCurrentSize++;
        if (!this.mDidFillOnce) {
            this.mLast++;
        }
        if (this.mLast >= this.mArrayIndices.length) {
            this.mDidFillOnce = true;
            this.mLast = this.mArrayIndices.length - 1;
        }
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public float use(ArrayRow definition, boolean removeFromDefinition) {
        float value = get(definition.mVariable);
        remove(definition.mVariable, removeFromDefinition);
        ArrayRow.ArrayRowVariables definitionVariables = definition.variables;
        int definitionSize = definitionVariables.getCurrentSize();
        for (int i = 0; i < definitionSize; i++) {
            SolverVariable definitionVariable = definitionVariables.getVariable(i);
            float definitionValue = definitionVariables.get(definitionVariable);
            add(definitionVariable, definitionValue * value, removeFromDefinition);
        }
        return value;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public final float remove(SolverVariable variable, boolean removeFromDefinition) {
        if (this.mCandidate == variable) {
            this.mCandidate = null;
        }
        if (this.mHead == -1) {
            return 0.0f;
        }
        int current = this.mHead;
        int previous = -1;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            int idx = this.mArrayIndices[current];
            if (idx == variable.id) {
                if (current == this.mHead) {
                    this.mHead = this.mArrayNextIndices[current];
                } else {
                    this.mArrayNextIndices[previous] = this.mArrayNextIndices[current];
                }
                if (removeFromDefinition) {
                    variable.removeFromRow(this.mRow);
                }
                variable.usageInRowCount--;
                this.mCurrentSize--;
                this.mArrayIndices[current] = -1;
                if (this.mDidFillOnce) {
                    this.mLast = current;
                }
                return this.mArrayValues[current];
            }
            previous = current;
            current = this.mArrayNextIndices[current];
        }
        return 0.0f;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public final void clear() {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            SolverVariable variable = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            if (variable != null) {
                variable.removeFromRow(this.mRow);
            }
            current = this.mArrayNextIndices[current];
        }
        this.mHead = -1;
        this.mLast = -1;
        this.mDidFillOnce = false;
        this.mCurrentSize = 0;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public boolean contains(SolverVariable variable) {
        if (this.mHead == -1) {
            return false;
        }
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (this.mArrayIndices[current] == variable.id) {
                return true;
            }
            current = this.mArrayNextIndices[current];
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public int indexOf(SolverVariable variable) {
        if (this.mHead == -1) {
            return -1;
        }
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (this.mArrayIndices[current] == variable.id) {
                return current;
            }
            current = this.mArrayNextIndices[current];
        }
        return -1;
    }

    boolean hasAtLeastOnePositiveVariable() {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (this.mArrayValues[current] > 0.0f) {
                return true;
            }
            current = this.mArrayNextIndices[current];
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public void invert() {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            float[] fArr = this.mArrayValues;
            fArr[current] = fArr[current] * (-1.0f);
            current = this.mArrayNextIndices[current];
        }
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public void divideByAmount(float amount) {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            float[] fArr = this.mArrayValues;
            fArr[current] = fArr[current] / amount;
            current = this.mArrayNextIndices[current];
        }
    }

    public int getHead() {
        return this.mHead;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public int getCurrentSize() {
        return this.mCurrentSize;
    }

    public final int getId(int index) {
        return this.mArrayIndices[index];
    }

    public final float getValue(int index) {
        return this.mArrayValues[index];
    }

    public final int getNextIndice(int index) {
        return this.mArrayNextIndices[index];
    }

    SolverVariable getPivotCandidate() {
        if (this.mCandidate == null) {
            int current = this.mHead;
            SolverVariable pivot = null;
            for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
                if (this.mArrayValues[current] < 0.0f) {
                    SolverVariable v = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
                    if (pivot == null || pivot.strength < v.strength) {
                        pivot = v;
                    }
                }
                current = this.mArrayNextIndices[current];
            }
            return pivot;
        }
        return this.mCandidate;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public SolverVariable getVariable(int index) {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (counter == index) {
                return this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            }
            current = this.mArrayNextIndices[current];
        }
        return null;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public float getVariableValue(int index) {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (counter == index) {
                return this.mArrayValues[current];
            }
            current = this.mArrayNextIndices[current];
        }
        return 0.0f;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public final float get(SolverVariable v) {
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            if (this.mArrayIndices[current] == v.id) {
                return this.mArrayValues[current];
            }
            current = this.mArrayNextIndices[current];
        }
        return 0.0f;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public int sizeInBytes() {
        int size = 0 + (this.mArrayIndices.length * 4 * 3);
        return size + 36;
    }

    @Override // androidx.constraintlayout.core.ArrayRow.ArrayRowVariables
    public void display() {
        int count = this.mCurrentSize;
        System.out.print("{ ");
        for (int i = 0; i < count; i++) {
            SolverVariable v = getVariable(i);
            if (v != null) {
                System.out.print(v + " = " + getVariableValue(i) + " ");
            }
        }
        System.out.println(" }");
    }

    public String toString() {
        String result = "";
        int current = this.mHead;
        for (int counter = 0; current != -1 && counter < this.mCurrentSize; counter++) {
            result = ((result + " -> ") + this.mArrayValues[current] + " : ") + this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            current = this.mArrayNextIndices[current];
        }
        return result;
    }
}
