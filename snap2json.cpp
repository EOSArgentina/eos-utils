/**
 *  @file
 *  @copyright
 */

#include <fc/io/raw.hpp>
#include <fc/io/json.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/optional.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/filesystem.hpp>

#include <eosio/chain/block_log.hpp>
#include <eosio/chain/fork_database.hpp>
#include <eosio/chain/exceptions.hpp>

#include <eosio/chain/account_object.hpp>
#include <eosio/chain/block_summary_object.hpp>
#include <eosio/chain/eosio_contract.hpp>
#include <eosio/chain/global_property_object.hpp>
#include <eosio/chain/contract_table_objects.hpp>
#include <eosio/chain/generated_transaction_object.hpp>
#include <eosio/chain/transaction_object.hpp>
#include <eosio/chain/reversible_block_object.hpp>

#include <eosio/chain/authorization_manager.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/chain_snapshot.hpp>
#include <eosio/chain/thread_utils.hpp>

#include <eosio/chain/chain_snapshot.hpp>
#include <eosio/chain/snapshot.hpp>
#include <eosio/chain/abi_serializer.hpp>

using namespace eosio;
using namespace eosio::chain;
using namespace eosio::chain::detail;
using namespace chainbase;
using namespace fc;
using namespace std;

#include <boost/program_options.hpp>

namespace po = boost::program_options;

struct snapshot_account_object {
   account_name         name;
   uint8_t              vm_type      = 0;
   uint8_t              vm_version   = 0;
   bool                 privileged   = false;

   time_point           last_code_update;
   digest_type          code_version;
   block_timestamp_type creation_date;

   vector<char>    code;
   vector<char>    abi;
};
FC_REFLECT(snapshot_account_object, (name)(vm_type)(vm_version)(privileged)(last_code_update)(code_version)(creation_date)(code)(abi))

struct snapshot_account_sequence_object {
   account_name name;
   uint64_t     recv_sequence;
   uint64_t     auth_sequence;
   uint64_t     code_sequence;
   uint64_t     abi_sequence;
};
FC_REFLECT(snapshot_account_sequence_object, (name)(recv_sequence)(auth_sequence)(code_sequence)(abi_sequence))

struct snapshot_table_id_object {
   account_name   code;
   scope_name     scope;
   table_name     table;
   account_name   payer;
   uint32_t       count = 0; /// the number of elements in the table
};
FC_REFLECT(snapshot_table_id_object, (code)(scope)(table)(payer)(count))

struct snapshot_key_value_object {
   uint64_t              primary_key;
   account_name          payer;
   vector<char>          value;
};
FC_REFLECT(snapshot_key_value_object, (primary_key)(payer)(value))

template <typename SecondaryKey>
struct snapshot_index_object {
   uint64_t      primary_key;
   account_name  payer = 0;
   SecondaryKey  secondary_key;
};

typedef snapshot_index_object<uint64_t>   snapshot_index64_object;
typedef snapshot_index_object<eosio::chain::uint128_t>  snapshot_index128_object;
typedef snapshot_index_object<key256_t>   snapshot_index256_object;
typedef snapshot_index_object<float64_t>  snapshot_index_double_object;
typedef snapshot_index_object<float128_t> snapshot_index_long_double_object;

REFLECT_SECONDARY(snapshot_index64_object)
REFLECT_SECONDARY(snapshot_index128_object)
REFLECT_SECONDARY(snapshot_index256_object)
REFLECT_SECONDARY(snapshot_index_double_object)
REFLECT_SECONDARY(snapshot_index_long_double_object)

int main(int argc, const char **argv) {

   try {

      std::string snapshot_path(argv[1]);

      FC_ASSERT( fc::is_regular_file(snapshot_path), 
         "snapshot named ${name} does not exists", ("name", snapshot_path));

      auto snap_in = std::ifstream(snapshot_path, (std::ios::in | std::ios::binary));
      istream_snapshot_reader isr(snap_in);

      auto read_section = [&](const string& section, auto F) {
         FC_ASSERT( isr.has_section(section) == true, 
            "${s} section does not exists", ("s", section));
         isr.read_section(section, F);
      };

      auto print_field = [](const string& name, const auto& value, bool add_sep=true) -> void {
         if(add_sep) cout << "," << endl;
         cout << "\"" << name << "\""
              << ":" 
              << json::to_string(value);
      };

      //Json begin
      cout << "{" << endl;
      print_field("____comment", fc::format_string("generated from snapshot file ${file}", fc::mutable_variant_object()("file", fc::path(argv[1]).filename())), false);

      //dump version
      read_section("eosio::chain::chain_snapshot_header", [&]( auto& s ) {
         FC_ASSERT( !s.empty(), "empty header" );
         chain_snapshot_header h;
         s.read_row(h);
         print_field("version", h.version);
      });

      //dump chain_id & genesis state
      read_section("eosio::chain::genesis_state", [&]( auto& s ) {
         FC_ASSERT( !s.empty(), "empty genesis_state" );
         genesis_state g;
         s.read_row(g);
         print_field("chain_id", g.compute_chain_id());
         print_field("genesis_state", g);
      });

      //dump block_header_state
      read_section("eosio::chain::block_state", [&]( auto& s ) {
         FC_ASSERT( !s.empty(), "empty block_state" );
         block_header_state h;
         s.read_row(h);
         print_field("block_state", h);
      });

      std::map<name, abi_def> abi_cache;

      //dump accounts
      read_section("eosio::chain::account_object", [&]( auto& s ) {         
         bool more = !s.empty();
         int cnt=0;
         cout << "," << endl << "\"accounts\": {" << endl;
         while(more) {
            snapshot_account_object acc;
            more = s.read_row(acc);
            print_field(acc.name.to_string(), acc, bool(cnt));
            ++cnt;

            try {
               abi_def abi;
               if(abi_serializer::to_abi(acc.abi, abi))
                  abi_cache.emplace(acc.name, std::move(abi));
            } catch(...){}
         }
         cout << endl << "}" << endl;
      });

      //dump permissions
      read_section("eosio::chain::permission_object", [&]( auto& s ) {         
         bool more = !s.empty();
         int cnt=0;
         int total=0;
         cout << "," << endl << "\"permissions\": {" << endl;
         account_name last;
         while(more) {
            snapshot_permission_object perm;
            more = s.read_row(perm);

            if(perm.owner != last) {
               if(cnt) cout << "}," << endl;
               cout << "\"" << perm.owner.to_string() << "\":{" << endl;
               cnt=0;
               ++total;
            }

            if(!perm.owner.empty()) {
               print_field(perm.name.to_string(), perm, bool(cnt));
               ++cnt;
            }
            last = perm.owner;
         }
         if(total) cout << "}" << endl;

         cout << endl << "}" << endl;
      }); 

      //dump account_sequence_object
      read_section("eosio::chain::account_sequence_object", [&]( auto& s ) {         
         bool more = !s.empty();
         int cnt=0;
         cout << "," << endl << "\"account_sequence\": {" << endl;
         while(more) {
            snapshot_account_sequence_object aso;
            more = s.read_row(aso);
            print_field(aso.name.to_string(), aso, bool(cnt));
            ++cnt;
         }
         cout << endl << "}" << endl;
      });

      //dump tables
      read_section("contract_tables", [&]( auto& s ) {         
         bool more = !s.empty();
         int cnt=0;
         cout << "," << endl << "\"tables\": [" << endl;
         while(more) {
            snapshot_table_id_object tid;
            more = s.read_row(tid);
            if(cnt) cout << ",";
            cout << "{"; 
               
               print_field("tid", tid, false);
               cout << ",\"rows\":[" << endl;
               
               unsigned_int size;
               more = s.read_row(size);
               
               fc::optional<abi_serializer> abis;
               if(abi_cache.count(tid.code)) {
                  abis = abi_serializer(abi_cache[tid.code], fc::milliseconds(20000));
               }

               for(unsigned_int i=0; i<size; ++i.value) {
                  snapshot_key_value_object kvo;
                  more = s.read_row(kvo);
                  if(i.value != 0) cout << ",";
                  try {
                     if(abis) {
                        auto v = abis->binary_to_variant(abis->get_table_type(tid.table), kvo.value, fc::milliseconds(20000) );
                        cout << json::to_string(v);
                     } else {
                        cout << json::to_string(kvo.value);
                     }
                  } catch(...) {
                     cout << "{}";
                  }
               }

               cout << "]" << endl;
               
               s.read_row(size);
               while(size.value-- > 0) {snapshot_index64_object tmp; s.read_row(tmp);}
               s.read_row(size);
               while(size.value-- > 0) {snapshot_index128_object tmp; s.read_row(tmp);}
               s.read_row(size);
               while(size.value-- > 0) {snapshot_index256_object tmp; s.read_row(tmp);}
               s.read_row(size);
               while(size.value-- > 0) {snapshot_index_double_object tmp; s.read_row(tmp);}
               more = s.read_row(size);
               while(size.value-- > 0) {snapshot_index_long_double_object tmp; more = s.read_row(tmp);}
               
            cout << "}" << endl;
            ++cnt;
         }
         cout << endl << "]" << endl;
      });

      //Json end
      cout << "}" << endl;

   } FC_CAPTURE_AND_LOG(());
   return 1;
}
