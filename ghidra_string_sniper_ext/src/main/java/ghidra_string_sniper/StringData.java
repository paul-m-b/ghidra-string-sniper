package ghidra_string_sniper;

import ghidra.program.model.address.Address;

public class StringData {
	public final String value;
	public final Address address;

	StringData(String value, Address address) {
		this.value = value;
		this.address = address;
	}
}
