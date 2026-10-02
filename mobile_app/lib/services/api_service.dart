import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiException implements Exception {
  final String message;
  ApiException(this.message);
  @override
  String toString() => message;
}

class ApiService {
  String baseUrl;
  String? token;
  ApiService(this.baseUrl);

  Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (token != null) 'Authorization': 'Bearer $token',
      };

  dynamic _handle(http.Response r) {
    dynamic data;
    try {
      data = jsonDecode(r.body);
    } catch (_) {
      throw ApiException('Unexpected server response');
    }
    if (r.statusCode >= 300) {
      throw ApiException((data is Map ? data['error'] : null) ?? 'Request failed');
    }
    return data;
  }

  Future<Map<String, dynamic>> register(
      String username, String password, String publicKey) async {
    final r = await http
        .post(Uri.parse('$baseUrl/api/register'),
            headers: _headers,
            body: jsonEncode(
                {'username': username, 'password': password, 'publicKey': publicKey}))
        .timeout(const Duration(seconds: 15));
    return Map<String, dynamic>.from(_handle(r));
  }

  Future<Map<String, dynamic>> login(String username, String password) async {
    final r = await http
        .post(Uri.parse('$baseUrl/api/login'),
            headers: _headers,
            body: jsonEncode({'username': username, 'password': password}))
        .timeout(const Duration(seconds: 15));
    return Map<String, dynamic>.from(_handle(r));
  }

  Future<String> publicKeyOf(String username) async {
    final r = await http
        .get(Uri.parse('$baseUrl/api/users/$username/key'), headers: _headers)
        .timeout(const Duration(seconds: 15));
    return _handle(r)['publicKey'] as String;
  }

  Future<List<Map<String, dynamic>>> searchUsers(String q) async {
    final r = await http
        .get(Uri.parse('$baseUrl/api/users?q=${Uri.encodeQueryComponent(q)}'),
            headers: _headers)
        .timeout(const Duration(seconds: 15));
    return (_handle(r) as List).map((e) => Map<String, dynamic>.from(e)).toList();
  }
}
