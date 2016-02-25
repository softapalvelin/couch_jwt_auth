rebar get-deps co eunit
# fix some incompatibility with couchdb plugins and rebar deps
for file in deps/*/ebin/*; do cp "$file" "ebin/$(basename $file)";done
for file in deps/*/priv/*.so; do cp "$file" "priv/$(basename $file)";done
