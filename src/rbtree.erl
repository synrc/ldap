%% @author Oleg Smirnov <oleg.smirnov@gmail.com>
%% @doc Red-black tree
%% Original code by Fuad Tabba (cs.auckland.ac.nz at fuad OR altabba.org at fuad)

-module(rbtree).
-export([insert/3, delete/2, lookup/2, issane/1]).

-type rb() :: r | b.
-type tree(K) :: {} | {K, term(), rb(), Left::tree(K), Right::tree(K)}.

-export_type([tree/1]).

-define(IS_BLACK(Tree), ((Tree =:= {}) orelse (element(3, Tree) =:= b))).

%% @doc Inserts a new node into the tree
-spec insert(K, term(), tree(K)) -> tree(K).
insert(Key, Value, Tree) ->
    % Invariant: Root must be black
    makeBlack(ins(Key, Value, Tree)).

%% @doc Removes an existing node from the tree
-spec delete(K, tree(K)) -> tree(K).
delete(Key, Tree) ->
    % Invariant: Root must be black
    fakenilfix(makeBlack(del(Key, Tree))).

%% @doc Gets the {Key, Value} tuple corresponding the the key
-spec lookup(K, tree(K)) -> {} | term().
lookup(_, {}) ->
    {};
lookup(Key, {Key, Value, _, _, _}) ->
    {Key, Value};
lookup(Key, {K2, _, _, Left, _}) when Key < K2  ->
    lookup(Key, Left);
lookup(Key, {K2, _, _, _, Right}) when Key > K2  ->
    lookup(Key, Right).

%% @doc Insertion Algorithm: do a BST insertion and balance as you go along
% Inserting a node into an empty tree: just add the node and color it red
ins(Key, Value, {}) ->
    {Key, Value, r, {}, {}};
% Collision with an existing key: leave the tree as it is
ins(Key, _, {Key, Value, Color, Left, Right}) ->
    {Key, Value, Color, Left, Right};
% Normal BST insertion (while rebalancing the tree)
ins(Key, Value, {Key2, Value2, Color, Left, Right}) when Key < Key2 ->
    balance({Key2, Value2, Color, ins(Key, Value, Left), Right});
ins(Key, Value, {Key2, Value2, Color, Left, Right}) when Key > Key2 ->
    balance({Key2, Value2, Color, Left, ins(Key, Value, Right)}).

%% @doc Rules for rebalancing the tree as described by Okasaki:-
%% http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps
balance({Kz, Vz, b, {Ky, Vy, r, {Kx, Vx, r, A, B}, C}, D}) ->
    {Ky, Vy, r, {Kx, Vx, b, A, B}, {Kz, Vz, b, C, D}};
balance({Kz, Vz, b, {Kx, Vx, r, A, {Ky, Vy, r, B, C}}, D}) ->
    {Ky, Vy, r, {Kx, Vx, b, A, B}, {Kz, Vz, b, C, D}};
balance({Kx, Vx, b, A, {Kz, Vz, r, {Ky, Vy, r, B, C}, D}}) ->
    {Ky, Vy, r, {Kx, Vx, b, A, B}, {Kz, Vz, b, C, D}};
balance({Kx, Vx, b, A, {Ky, Vy, r, B, {Kz, Vz, r, C, D}}}) ->
    {Ky, Vy, r, {Kx, Vx, b, A, B}, {Kz, Vz, b, C, D}};
balance(Tree) ->
    Tree.

%% @doc An RB-Tree invariant
makeBlack({}) ->
    {};
makeBlack({Key, Value, _, Left, Right}) ->
    {Key, Value, b, Left, Right}.

%% @doc Deletion: do a BST deletion and fix the mess as you go
% Deleting from an empty tree: do nothing
del(_, {}) ->
    {};
% Deleting a red node, doesn't violate RB invariants
del(Key, {Key, _, r, Child, {}}) ->
    Child;
del(Key, {Key, _, r, {}, Child}) ->
    Child;
% Deleting a black node - violates invariants, give child a black token to
% indicate that subtree is missing a black node
del(Key, {Key, _, b, Child, {}}) ->
    blackToken(Child);
del(Key, {Key, _, b, {}, Child}) ->
    blackToken(Child);
% Normal BST deletion (while fixing any messes being made)
del(Key, {Key, _, Color, Left, Right}) ->
    {Km, Vm} = max(Left),
    delfix({Km, Vm, Color, del(Km, Left), Right});
del(Key, {K2, V2, C2, Left, Right}) when Key < K2  ->
    delfix({K2, V2, C2, del(Key, Left), Right});
del(Key, {K2, V2, C2, Left, Right}) when Key > K2  ->
    delfix({K2, V2, C2, Left, del(Key, Right)}).

%% @doc Fixing the red black tree after a deletion, based on:-
%% http://sage.mc.yu.edu/kbeen/teaching/algorithms/resources/red-black-tree.html
% Case A (partial - doesn't handle making the root black):
blackToken({Key, Value, r, Left, Right}) ->
    {Key, Value, b, Left, Right};
% A black node becomes doubly black
blackToken({Key, Value, b, Left, Right}) ->
    {Key, Value, bb, Left, Right};
% An empty leaf (which is actually black, becomes doubly black).
blackToken({}) ->
    {fakenil, 0, bb, {}, {}}. % transient node, removed before the end of the operation

%% @doc Reverts a fakenil into {} once it loses its token
%% Apply to all cases where a node potentially loses a token
fakenilfix({fakenil, 0, b, {}, {}}) ->
    {};
fakenilfix(Tree) ->
    Tree.

%% @doc Applies cases B, C and D
% Case B
delfix({Ky, Vy, Cy, {Kx, Vx, bb, A, B}, {Kz, Vz, b, C, D}}) when ?IS_BLACK(C) andalso ?IS_BLACK(D) ->
    blackToken({Ky, Vy, Cy, fakenilfix({Kx, Vx, b, A, B}), {Kz, Vz, r, C, D}});
delfix({Ky, Vy, Cy, {Kx, Vx, b, A, B}, {Kz, Vz, bb, C, D}}) when ?IS_BLACK(A) andalso ?IS_BLACK(B)->
    blackToken({Ky, Vy, Cy, {Kx, Vx, r, A, B}, fakenilfix({Kz, Vz, b, C, D})});
% Case C
delfix({Ky, Vy, b, {Kx, Vx, bb, A, B}, {Kz, Vz, r, C, D}}) when ?IS_BLACK(C) andalso ?IS_BLACK(D)->
    {Kz, Vz, b, delfix({Ky, Vy, r, {Kx, Vx, bb, A, B}, C}), D};
delfix({Ky, Vy, b, {Kx, Vx, r, A, B}, {Kz, Vz, bb, C, D}}) when ?IS_BLACK(A) andalso ?IS_BLACK(B)->
    {Kx, Vx, b, A, delfix({Ky, Vy, r, B, {Kz, Vz, bb, C, D}})};
% Case D
% Subcase i
delfix({Ky, Vy, Cy, {Kx, Vx, bb, A, B}, {Kw, Vw, b, {Kz, Vz, r, C, D}, E}}) when ?IS_BLACK(E) ->
    delfix({Ky, Vy, Cy, {Kx, Vx, bb, A, B}, {Kz, Vz, b, C, {Kw, Vw, r, D, E}}});
delfix({Kz, Vz, Cz, {Kx, Vx, b, A, {Ky, Vy, r, B, C}}, {Kw, Vw, bb, D, E}}) when ?IS_BLACK(A) ->
    delfix({Kz, Vz, Cz, {Ky, Vy, b, {Kx, Vx, r, A, B}, C}, {Kw, Vw, bb, D, E}});
% Subcase ii
delfix({Ky, Vy, Cy, {Kx, Vx, bb, A, B}, {Kz, Vz, b, C, {Kw, Vw, r, D, E}}}) when ?IS_BLACK(E) ->
    {Kz, Vz, Cy, {Ky, Vy, b, fakenilfix({Kx, Vx, b, A, B}), C}, {Kw, Vw, b, D, E}}; % z takes on y's color
delfix({Kz, Vz, Cz, {Ky, Vy, b, {Kx, Vx, r, A, B}, C}, {Kw, Vw, bb, D, E}}) when ?IS_BLACK(A) ->
    {Ky, Vy, Cz, {Kx, Vx, b, A, B}, {Kz, Vz, b, C, fakenilfix({Kw, Vw, b, D, E})}}; % y takes on z's color
% All other cases, leave it as it is
delfix(Tree) ->
    Tree.

%% @doc Get the maximum value in the tree (used when deleting nodes)
max({Key, Value, _, _, {}}) ->
    {Key, Value};
max({_, _, _, _, Right}) ->
    max(Right).

%% @doc Performs a sanity check on the tree, check for all the BST and RB invariants
-spec issane(tree(term())) -> boolean().
issane({}) ->
    true;
% Root must be black
issane({_, _, r, _, _}) ->
    false;
issane(T) ->
    checkbstorder(T) andalso checkrbproperty(T) andalso (countblack(T) =/= false).

%% @doc Check that the binary search tree invariants (ordering) are held
checkbstorder({_, _, _, {}, {}}) ->
    true;
checkbstorder({Key, _, _, {}, Right}) ->
   {Kr, _, _, _, _} = Right,
   (Key < Kr) andalso checkbstorder(Right);
checkbstorder({Key, _, _, Left, {}}) ->
   {Kl, _, _, _, _} = Left,
   (Kl < Key) andalso checkbstorder(Left);
checkbstorder({Key, _, _, Left, Right}) ->
   {Kl, _, _, _, _} = Left,
   {Kr, _, _, _, _} = Right,
   (Kl < Key) andalso (Key < Kr) andalso checkbstorder(Left) andalso checkbstorder(Right).

%% @doc Check that there aren't two red nodes in a row.
checkrbproperty({}) ->
    true;
checkrbproperty({_, _, b, Left, Right}) ->
    checkrbproperty(Left) andalso checkrbproperty(Right);
checkrbproperty({_, _, r, Left, Right}) ->
    checkrbred(Left) andalso checkrbred(Right).

checkrbred({}) ->
    true;
checkrbred({_, _, b, Left, Right}) ->
    checkrbproperty(Left) andalso checkrbproperty(Right);
checkrbred({_, _, r, _, _}) ->
    false.

%% @doc Check that the number of black nodes is equal in all paths to the leaves
% Leaves aren't counted (Even though they are technically black, doesn't matter)
countblack({}) ->
    0;
countblack({_, _, b, Left, Right}) ->
    CountLeft = countblack(Left),
    CountRight = countblack(Right),
    if
        (CountLeft =:= CountRight) andalso (CountLeft =/= false) ->
            1 + CountLeft;
        true -> false
    end;
countblack({_, _, r, Left, Right}) ->
    CountLeft = countblack(Left),
    CountRight = countblack(Right),
    if
        (CountLeft =:= CountRight) andalso (CountLeft =/= false) ->
            CountLeft;
        true -> false
    end.
