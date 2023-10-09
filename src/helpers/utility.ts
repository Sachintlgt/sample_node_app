export default {
	randomNumber: function (length: number) {
		var text = "";
		var possible = "123456789";
		for (var i = 0; i < length; i++) {
			var sup = Math.floor(Math.random() * possible.length);
			text += i > 0 && sup == i ? "0" : possible.charAt(sup);
		}
		return Number(text);
	},
	titleCase: function (str: string) {
		var splitStr = str.toLowerCase().split(' ');
		for (var i = 0; i < splitStr.length; i++) {
			splitStr[i] = splitStr[i].charAt(0).toUpperCase() + splitStr[i].substring(1);     
		}
		return splitStr.join(' '); 
	}
};
