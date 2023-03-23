import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart' hide Key;
import 'package:pointycastle/api.dart' hide Padding;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/cbc.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'KinID AES-128-CBC Decryption PoC'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final _formKey = GlobalKey<FormState>();
  final _keyController = TextEditingController(),
      _dataController = TextEditingController(),
      _ivController = TextEditingController(),
      _decryptedController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Padding(
        padding: const EdgeInsets.only(left: 16, right: 16, bottom: 16),
        child: Center(
          child: Form(
            key: _formKey,
            child: ListView(
              children: <Widget>[
                Padding(
                  padding: const EdgeInsets.only(bottom: 16, top: 16),
                  child: TextFormField(
                      controller: _keyController,
                      validator: (value) {
                        if (value == null || value.isEmpty) {
                          return "128 Bit Key is required";
                        } else if (value.length != 16) {
                          return "Need 16-bit Key (16 characters)";
                        } else {
                          return null;
                        }
                      },
                      decoration: const InputDecoration(
                          labelText: "128 Key", border: OutlineInputBorder())),
                ),
                Padding(
                  padding: const EdgeInsets.only(bottom: 16),
                  child: TextFormField(
                      controller: _ivController,
                      validator: (value) {
                        if (value == null || value.isEmpty) {
                          return "IV is required";
                        } else if (value.length != 16) {
                          return "Need 16-bit IV (16 characters)";
                        } else {
                          return null;
                        }
                      },
                      decoration: const InputDecoration(
                          labelText: "IV", border: OutlineInputBorder())),
                ),
                Padding(
                  padding: const EdgeInsets.only(bottom: 16),
                  child: TextFormField(
                      controller: _dataController,
                      validator: (value) {
                        bool isBase64;
                        List<int>? base64DecodedData;
                        try {
                          base64DecodedData = base64Decode(value ?? "");
                          isBase64 = true;
                        } catch (e, s) {
                          isBase64 = false;
                        }
                        if (value == null || value.isEmpty) {
                          return "Data is required";
                        } else if (!isBase64) {
                          return "Must be Base 64 encoded string";
                        } else if (base64DecodedData!.length % 16 != 0) {
                          return "Base 64 string length must be a multiple of 16";
                        } else {
                          return null;
                        }
                      },
                      decoration: const InputDecoration(
                          labelText: "Encrypted Data (Base 64)",
                          border: OutlineInputBorder())),
                ),
                Padding(
                  padding: const EdgeInsets.only(bottom: 48),
                  child: Row(
                    children: [
                      Expanded(
                          child: ElevatedButton(
                              onPressed: () {
                                if (_formKey.currentState!.validate()) {
                                  final key = Uint8List.fromList(
                                      utf8.encode(_keyController.text));
                                  final encryptedData =
                                      base64Decode(_dataController.text);
                                  final iv = Uint8List.fromList(
                                      utf8.encode(_ivController.text));
                                  final cbc = CBCBlockCipher(AESEngine())
                                    ..init(
                                        false,
                                        ParametersWithIV(
                                            KeyParameter(key), iv));
                                  var offset = 0;
                                  final decryptedData =
                                      Uint8List(encryptedData.length);
                                  while (offset < encryptedData.length) {
                                    offset += cbc.processBlock(encryptedData,
                                        offset, decryptedData, offset);
                                  }
                                  _decryptedController.text = utf8.decode(
                                      decryptedData
                                          .takeWhile((value) => value >= 0x20)
                                          .toList());
                                }
                              },
                              child: const Text("Decrypt"))),
                    ],
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.only(bottom: 16),
                  child: TextFormField(
                      controller: _decryptedController,
                      readOnly: true,
                      decoration: const InputDecoration(
                          labelText: "Decrypted Data",
                          border: OutlineInputBorder())),
                ),
              ],
            ),
          ),
        ),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
