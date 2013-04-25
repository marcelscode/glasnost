package resource {
	import mx.core.ByteArrayAsset;
	
	public final class Resource {
		[Embed (source="protocols.spec.marshalled", mimeType="application/octet-stream")]
		public static const Protocols:Class;
		
		public function Resource() {
//			var ba:ByteArrayAsset = ByteArrayAsset( new Protocols() );
//			trace("Read first byte: " + ba.readByte());
//			trace("Read 2nd byte: " + ba.readByte());
//			trace("Read 3rd byte: " + ba.readByte());
		}
		
		public static function getBuiltInProtocols():ByteArrayAsset {
			return ByteArrayAsset( new Protocols() );
		}
	}
}