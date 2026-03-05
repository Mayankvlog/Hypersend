import 'package:flutter/material.dart';
import 'package:geolocator/geolocator.dart';
import 'package:geocoding/geocoding.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:permission_handler/permission_handler.dart';

class LocationPickerScreen extends StatefulWidget {
  final double? initialLatitude;
  final double? initialLongitude;

  const LocationPickerScreen({
    super.key,
    this.initialLatitude,
    this.initialLongitude,
  });

  @override
  State<LocationPickerScreen> createState() => _LocationPickerScreenState();
}

class _LocationPickerScreenState extends State<LocationPickerScreen> {
  GoogleMapController? _mapController;
  LatLng? _selectedLocation;
  Marker? _selectedMarker;
  bool _loading = false;
  String? _address;
  Set<Marker> _markers = {};

  @override
  void dispose() {
    _mapController?.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    if (widget.initialLatitude != null && widget.initialLongitude != null) {
      _selectedLocation = LatLng(widget.initialLatitude!, widget.initialLongitude!);
      _selectedMarker = Marker(
        markerId: const MarkerId('selected'),
        position: _selectedLocation!,
        infoWindow: const InfoWindow(title: 'Selected Location'),
      );
      _markers.add(_selectedMarker!);
      _getAddress(_selectedLocation!);
    }
  }

  Future<bool> _requestLocationPermission() async {
    final status = await Permission.location.request();
    if (status != PermissionStatus.granted) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Location permission is required to share your location')),
        );
      }
      return false;
    }
    return true;
  }

  Future<void> _getCurrentLocation() async {
    setState(() => _loading = true);
    
    try {
      final granted = await _requestLocationPermission();
      if (!granted) {
        return; // Let finally block handle _loading = false
      }
      
      final position = await Geolocator.getCurrentPosition(
        desiredAccuracy: LocationAccuracy.high,
      );

      final location = LatLng(position.latitude, position.longitude);
      _updateSelectedLocation(location);
      
      // Move map to current location
      _mapController?.animateCamera(
        CameraUpdate.newCameraPosition(
          CameraPosition(target: location, zoom: 15),
        ),
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to get location: $e')),
        );
      }
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _getAddress(LatLng location) async {
    try {
      final placemarks = await placemarkFromCoordinates(
        location.latitude,
        location.longitude,
      );
      
      if (placemarks.isNotEmpty && mounted) {
        final place = placemarks.first;
        setState(() {
          _address = _formatAddress(place);
        });
      }
    } catch (e) {
      // Address lookup failed, but that's okay
      debugPrint('Failed to get address: $e');
    }
  }

  String _formatAddress(Placemark place) {
    final parts = <String>[];
    if (place.street?.isNotEmpty == true) parts.add(place.street!);
    if (place.subLocality?.isNotEmpty == true) parts.add(place.subLocality!);
    if (place.locality?.isNotEmpty == true) parts.add(place.locality!);
    if (place.administrativeArea?.isNotEmpty == true) parts.add(place.administrativeArea!);
    if (place.country?.isNotEmpty == true) parts.add(place.country!);
    
    return parts.isNotEmpty ? parts.join(', ') : 'Unknown Location';
  }

  void _updateSelectedLocation(LatLng location) {
    setState(() {
      _selectedLocation = location;
      _selectedMarker = Marker(
        markerId: const MarkerId('selected'),
        position: location,
        infoWindow: const InfoWindow(title: 'Selected Location'),
      );
      _markers = {_selectedMarker!};
    });
    _getAddress(location);
  }

  void _onMapTap(LatLng location) {
    _updateSelectedLocation(location);
  }

  void _onMapCreated(GoogleMapController controller) {
    _mapController = controller;
  }

  void _confirmLocation() {
    if (_selectedLocation == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please select a location')),
      );
      return;
    }

    Navigator.pop(context, {
      'latitude': _selectedLocation!.latitude,
      'longitude': _selectedLocation!.longitude,
      'address': _address,
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Share Location'),
        backgroundColor: Colors.black87,
        foregroundColor: Colors.white,
        actions: [
          if (_selectedLocation != null)
            TextButton(
              onPressed: _confirmLocation,
              child: const Text(
                'Send',
                style: TextStyle(
                  color: Colors.cyan,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
        ],
      ),
      backgroundColor: Colors.black87,
      body: Column(
        children: [
          // Address display
          if (_address != null)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              color: Colors.grey[900],
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Selected Location:',
                    style: TextStyle(
                      color: Colors.grey,
                      fontSize: 12,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    _address!,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                    ),
                  ),
                ],
              ),
            ),
          
          // Map
          Expanded(
            child: Stack(
              children: [
                GoogleMap(
                  initialCameraPosition: CameraPosition(
                    target: _selectedLocation ?? const LatLng(37.7749, -122.4194),
                    zoom: 15,
                  ),
                  markers: _markers,
                  onTap: _onMapTap,
                  onMapCreated: _onMapCreated,
                  myLocationEnabled: true,
                  myLocationButtonEnabled: false,
                  mapType: MapType.normal,
                ),
                
                // Current location button
                Positioned(
                  right: 16,
                  bottom: 100,
                  child: FloatingActionButton(
                    heroTag: "current_location",
                    onPressed: _getCurrentLocation,
                    backgroundColor: Colors.cyan,
                    child: _loading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                            ),
                          )
                        : const Icon(Icons.my_location),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
