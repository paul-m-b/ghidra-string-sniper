package ghidra_string_sniper;

public class ResultData {
	StringData string;
	float confidence;

	public ResultData(float confidence, StringData string) {
		this.confidence = confidence;
		this.string = string;
	}
}
