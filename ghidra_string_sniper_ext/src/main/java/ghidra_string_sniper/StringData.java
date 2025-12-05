package ghidra_string_sniper;

public class StringData {
    public String value;      // actual string text
    public String address;    // hash stored as string for now
    public Float score;       // optional confidence score

    // Original 2-argument constructor (rest of project depends on this)
    public StringData(String value, String address) {
        this.value = value;
        this.address = address;
        this.score = null;
    }

    // Optional 3-argument constructor (for analysis/prioritization features)
    public StringData(String value, String address, Float score) {
        this.value = value;     // <-- ensure value = extracted text
        this.address = address; // <-- hash
        this.score = score;
    }

    @Override
    public String toString() {
        return value;
    }
}
