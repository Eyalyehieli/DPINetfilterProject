package packetsNetFilterDB;

public class ProtocolItem 
{
	private String ip;
	private int port;
	private String typeOfProperty;
	private /*Object*/String minRange;
	private /*Object*/String maxRange;
	
	public ProtocolItem(String ip,int port,String typeOfProperty,String minRange,String maxRange)
	{
		this.ip=ip;
		this.port=port;
		this.typeOfProperty=typeOfProperty;
		this.minRange=minRange;//TypeFactory.getRange(typeOfProperty, minRange);
		this.maxRange=maxRange;//TypeFactory.getRange(typeOfProperty,maxRange);
	}

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getTypeOfProperty() {
		return typeOfProperty;
	}

	public void setTypeOfProperty(String typeOfProperty) {
		this.typeOfProperty = typeOfProperty;
	}

	public String getMinRange() {
		return minRange;
	}

	public void setMinRange(String minRange) {
		this.minRange = minRange;
	}

	public String getMaxRange() {
		return maxRange;
	}

	public void setMaxRange(String maxRange) {
		this.maxRange = maxRange;
	}
}
