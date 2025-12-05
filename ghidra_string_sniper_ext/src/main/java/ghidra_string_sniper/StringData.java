package ghidra_string_sniper;

public class StringData {
    public String value;      // actual string text
    public String address;    // hash stored as string for now
    public Float score;       // optional confidence score

	public Integer resultsScore;       
	public Float entropy;
	

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


    public StringData(String value, String address, Float score, Integer resultsScore, Float entropy) {
        this.value = value;     // <-- ensure value = extracted text
        this.address = address; // <-- hash
        this.score = score;
		this.resultsScore = resultsScore;
		this.entropy = entropy;
    }




    @Override
    public String toString() {
        return value;
    }
}
