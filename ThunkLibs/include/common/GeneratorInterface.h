namespace fexgen {
struct returns_guest_pointer {};
struct custom_host_impl {};
struct custom_guest_entrypoint {};

struct generate_guest_symtable {};
struct indirect_guest_calls {};

struct callback_annotation_base {
  // Prevent annotating multiple callback strategies
  bool prevent_multiple;
};
struct callback_stub : callback_annotation_base {};

// Member annotation to mark members handled by custom repacking. This enables
// automatic struct repacking of structs with non-trivial members (pointers,
// unions, ...). Repacking logic is auto-generated as usual, with the
// difference that an external function is called to manually repack the
// annotated members.
//
// Two functions must be implemented for the parent struct type:
// * fex_custom_repack_entry, called after automatic repacking of the other members
// * fex_custom_repack_exit, called on exit but before automatic exit-repacking
//     of the other members. Non-trivial implementations must perform host->guest
//     repacking manually and return the boolean value true.
//
// If multiple members of the same struct are annotated as custom_repack,
// they must be handled in the same fex_custom_repack_entry/exit functions.
struct custom_repack {};

// Member annotation for a pointer member that points to an array of elements
// rather than to a single one, naming the sibling member that holds the count:
//
//   template<> struct fex_gen_config<&VkWriteDescriptorSet::pImageInfo>
//     : fexgen::array_length_from<&VkWriteDescriptorSet::descriptorCount> {};
//
// Without this the generator has no way to know how many elements to convert.
// It therefore scored a pointer to a merely-repackable struct as
// TypeCompatibility::None -- "automatic repacking isn't possible" -- and every
// function taking such a struct was rejected outright. With the count in hand
// the array is repacked element-wise, so those functions become expressible
// without hand-written repacking.
//
// The annotated member is filled in by generated code, so it is skipped by the
// automatic member-wise conversion, exactly like custom_repack. Elements are
// converted recursively, so an element type that itself has annotated arrays
// works.
//
// NOTE: a struct carrying one of these is treated as fully handled on exit
// (its other members are not automatically converted back). That matches how
// custom_repack structs already behave and suits the API inputs these appear
// on; a struct that is genuinely an out-parameter needs custom_repack instead.
template<auto CountMember>
struct array_length_from {};

// Type annotation to indicate that guest_layout/host_layout definitions should
// be emitted even if the type is non-repackable. Pointer members will be
// copied (or zero-extended) without regard for the referred data.
struct emit_layout_wrappers {};

struct type_annotation_base {
  bool prevent_multiple;
};

// Pointers to types annotated with this will be passed through without change
struct opaque_type : type_annotation_base {};

// Function parameter annotation.
// Pointers are passed through to host (extending to 64-bit if needed) without modifying the pointee.
// The type passed to Host will be guest_layout<pointee_type>*.
struct ptr_passthrough {};

// Type / Function parameter annotation.
// Assume objects of the given type are compatible across architectures,
// even if the generator can't automatically prove this. For pointers, this refers to the pointee type.
// NOTE: In contrast to opaque_type, this allows for non-pointer members with the annotated type to be repacked automatically.
struct assume_compatible_data_layout : type_annotation_base {};

} // namespace fexgen
