import 'package:equatable/equatable.dart';
import 'package:flutter/material.dart';

class Permission extends Equatable {
  final String id;
  final String title;
  final String description;
  final IconData icon;
  final bool isGranted;

  const Permission({
    required this.id,
    required this.title,
    required this.description,
    required this.icon,
    this.isGranted = false,
  });

  @override
  List<Object?> get props => [id, title, description, icon, isGranted];

  Permission copyWith({
    String? id,
    String? title,
    String? description,
    IconData? icon,
    bool? isGranted,
  }) {
    return Permission(
      id: id ?? this.id,
      title: title ?? this.title,
      description: description ?? this.description,
      icon: icon ?? this.icon,
      isGranted: isGranted ?? this.isGranted,
    );
  }
}